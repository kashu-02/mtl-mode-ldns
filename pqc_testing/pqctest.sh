#!/bin/bash
APPDIR="../examples"

mtl_dnssec_keygen_sign_and_verify () {
    ALGORITHMS=$@
    echo ""
    rm -rf Kexample.com.*

    echo -e "\033[0;34mTesting Valid Keys\033[0m"
    echo " Generating Keys - $ALGORITHMS"
    for alg in $ALGORITHMS
    do
        $APPDIR/ldns-keygen -a $alg -b 2049 example.com >> /dev/null
        $APPDIR/ldns-keygen -k -a $alg example.com >> /dev/null
    done

    echo " Signing zone example.com" 
    KEYS=$(ls Kexample.com.*.key | sed 's/.key//g')

    $APPDIR/ldns-signzone -n example.com $KEYS   

    echo " Verifying zone example.com" 
    KEYS=$(ls Kexample.com.*.ds)

    FLAGS=""
    for k in $KEYS; do
        FLAGS="$FLAGS -k $k"
    done

    $APPDIR/ldns-verify-zone -V 3 example.com.signed $FLAGS
    if [ $? -eq 0 ]; then
       echo -e "\033[0;32mTest Passed\033[0m"
    else 
       echo -e "\033[0;31mTest Failed\033[0m"
       exit -1
    fi

    rm -rf Kexample.com.*
}

mtl_dnssec_test_mismatch_keys () {
    ALGORITHMS=$@
    echo ""
    rm -rf Kexample.com.*

    echo -e "\033[0;34mTesting Mismatched Keys\033[0m"
    echo " Generating Keys - $ALGORITHMS"
    for alg in $ALGORITHMS
    do
        $APPDIR/ldns-keygen -a $alg -b 2049 example.com >> /dev/null
        $APPDIR/ldns-keygen -k -a $alg example.com >> /dev/null
    done

    echo " Verifying zone example.com" 
    KEYS=$(ls Kexample.com.*.ds)

    FLAGS=""
    for k in $KEYS; do
        FLAGS="$FLAGS -k $k"
    done

    $APPDIR/ldns-verify-zone -V 3 example.com.signed $FLAGS   
    if [ $? -ne 0 ]; then
       echo -e "\033[0;32mTest Passed\033[0m"
    else 
       echo -e "\033[0;31mTest Failed\033[0m"
       exit -1
    fi

    rm -rf Kexample.com.*
}


mtl_dnssec_test_missing_soa_sig () {
    ALGORITHMS=$@
    echo ""
    rm -rf Kexample.com.*

    echo -e "\033[0;34mTesting Missing SOA Signature\033[0m"
    echo " Generating Keys - $ALGORITHMS"
    for alg in $ALGORITHMS
    do
        $APPDIR/ldns-keygen -a $alg -b 2049 example.com >> /dev/null
        $APPDIR/ldns-keygen -k -a $alg example.com >> /dev/null
    done

    echo " Signing zone example.com" 
    KEYS=$(ls Kexample.com.*.key | sed 's/.key//g')

    $APPDIR/ldns-signzone -n example.com $KEYS   

    # Remove the SOA signature
    sed -i '/IN	RRSIG	SOA/d' ./example.com.signed

    echo " Verifying zone example.com" 
    KEYS=$(ls Kexample.com.*.ds)

    FLAGS=""
    for k in $KEYS; do
        FLAGS="$FLAGS -k $k"
    done

    $APPDIR/ldns-verify-zone -V 3 example.com.signed $FLAGS
    if [ $? -ne 0 ]; then
       echo -e "\033[0;32mTest Passed\033[0m"
    else 
       echo -e "\033[0;31mTest Failed\033[0m"
       exit -1
    fi

    rm -rf Kexample.com.*
}


mtl_dnssec_test_soa_incorrect () {
    ALGORITHMS=$@
    echo ""
    rm -rf Kexample.com.*

    echo -e "\033[0;34mTesting Invalid SOA Signature\033[0m"
    echo " Generating Keys - $ALGORITHMS"
    for alg in $ALGORITHMS
    do
        $APPDIR/ldns-keygen -a $alg -b 2049 example.com >> /dev/null
        $APPDIR/ldns-keygen -k -a $alg example.com >> /dev/null
    done

    echo " Signing zone example.com" 
    KEYS=$(ls Kexample.com.*.key | sed 's/.key//g')

    $APPDIR/ldns-signzone -n example.com $KEYS   

    # Replace the SOA signature with the one for the AAAA record
    # Which is a valid condensed signature but won't verify with this message
    SOA_RRSIG=$(grep 'IN	RRSIG	SOA' ./example.com.signed | awk '{$NF=""; print $0}')
    sed -i '/IN	RRSIG	SOA/d' ./example.com.signed    
    AAAA_RRSIG=$(grep 'IN	RRSIG	AAAA' ./example.com.signed | awk 'NF>1{print $NF}')
    echo $SOA_RRSIG $AAAA_RRSIG >> ./example.com.signed

    echo " Verifying zone example.com" 
    KEYS=$(ls Kexample.com.*.ds)

    FLAGS=""
    for k in $KEYS; do
        FLAGS="$FLAGS -k $k"
    done

    $APPDIR/ldns-verify-zone -V 3 example.com.signed $FLAGS
    if [ $? -ne 0 ]; then
       echo -e "\033[0;32mTest Passed\033[0m"
    else 
       echo -e "\033[0;31mTest Failed\033[0m"
       exit -1
    fi

    rm -rf Kexample.com.*
}

clear

mtl_dnssec_keygen_sign_and_verify SLH_DSA_MTL_SHA2_128s
mtl_dnssec_keygen_sign_and_verify SLH_DSA_MTL_SHAKE_128s
mtl_dnssec_keygen_sign_and_verify SLH_DSA_MTL_SHA2_128s SLH_DSA_MTL_SHAKE_128s

mtl_dnssec_test_mismatch_keys SLH_DSA_MTL_SHA2_128s
mtl_dnssec_test_mismatch_keys SLH_DSA_MTL_SHAKE_128s
mtl_dnssec_test_mismatch_keys SLH_DSA_MTL_SHA2_128s SLH_DSA_MTL_SHAKE_128s

mtl_dnssec_test_missing_soa_sig SLH_DSA_MTL_SHA2_128s
mtl_dnssec_test_missing_soa_sig SLH_DSA_MTL_SHAKE_128s
mtl_dnssec_test_missing_soa_sig SLH_DSA_MTL_SHA2_128s SLH_DSA_MTL_SHAKE_128s

mtl_dnssec_test_soa_incorrect SLH_DSA_MTL_SHA2_128s
mtl_dnssec_test_soa_incorrect SLH_DSA_MTL_SHAKE_128s
mtl_dnssec_test_soa_incorrect SLH_DSA_MTL_SHA2_128s SLH_DSA_MTL_SHAKE_128s

mtl_dnssec_keygen_sign_and_verify FL_DSA_512
mtl_dnssec_keygen_sign_and_verify ML_DSA_44
mtl_dnssec_keygen_sign_and_verify SLH_DSA_SHA2_128s
mtl_dnssec_keygen_sign_and_verify SLH_DSA_SHAKE_128s
mtl_dnssec_keygen_sign_and_verify FL_DSA_512 ML_DSA_44 SLH_DSA_SHA2_128s SLH_DSA_SHAKE_128s

mtl_dnssec_test_mismatch_keys FL_DSA_512
mtl_dnssec_test_mismatch_keys ML_DSA_44
mtl_dnssec_test_mismatch_keys SLH_DSA_SHA2_128s
mtl_dnssec_test_mismatch_keys SLH_DSA_SHAKE_128s
mtl_dnssec_test_mismatch_keys FL_DSA_512 ML_DSA_44 SLH_DSA_SHA2_128s SLH_DSA_SHAKE_128s

echo ""
echo -e "\033[0;32mTesting is complete - All Tests Pass!\033[0m"
exit 0