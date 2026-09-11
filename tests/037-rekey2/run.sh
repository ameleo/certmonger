#!/bin/bash -e

cd "$tmpdir"

CERTMONGER_CONFIG_DIR="$tmpdir"
export CERTMONGER_CONFIG_DIR

source "$srcdir"/functions

# Set a "maximum" key lifetime of 68 years, for the sake of systems where I
# don't want to work around 32-bit time_t just now.
echo '[Lifetime = 68y.]'
cat > certmonger.conf << EOF
[defaults]
notification_method=STDERR
max_key_use_count=20
max_key_lifetime=68y
[selfsign]
validity_period=1y
EOF

# Issue on 2000-01-01 for one year.
cat > ca.self <<- EOF
id=Self
ca_is_default=0
ca_type=INTERNAL:SELF
ca_internal_serial=1235
ca_internal_issue_time=946684800
EOF

# Set up a basic certificate.
cat > entry.openssl <<- EOF
id=Test
ca_name=Self
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile
autorenew=1
EOF

# Run through the whole enrollment process.
$toolsdir/iterate ca.self entry.openssl NEED_KEY_PAIR,GENERATING_KEY_PAIR,HAVE_KEY_PAIR
$toolsdir/iterate ca.self entry.openssl NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO,NEED_CSR
$toolsdir/iterate ca.self entry.openssl NEED_CSR,GENERATING_CSR,HAVE_CSR
$toolsdir/iterate ca.self entry.openssl NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca.self entry.openssl NEED_TO_SAVE_CERT,START_SAVING_CERT,SAVING_CERT
$toolsdir/iterate ca.self entry.openssl NEED_TO_SAVE_CA_CERTS,START_SAVING_CA_CERTS,SAVING_CA_CERTS
$toolsdir/iterate ca.self entry.openssl NEED_TO_READ_CERT,READING_CERT,SAVED_CERT
$toolsdir/iterate ca.self entry.openssl NEED_TO_NOTIFY_ISSUED_SAVED,NOTIFYING_ISSUED_SAVED

# Now kick it and see what we decide to do next.  Expect NEED_CSR/HAVE_KEY_PAIR.
echo key_generated_date=20000101000000 >> entry.openssl
$toolsdir/iterate ca.self entry.openssl MONITORING

rm -f ca.self entry.openssl keyfile certfile

# Set a "maximum" key lifetime of 1 year.
echo '[Lifetime = 1y.]'
cat > certmonger.conf << EOF
[defaults]
notification_method=STDERR
max_key_use_count=20
max_key_lifetime=1y
[selfsign]
validity_period=1y
EOF

# Issue on 2000-01-01 for one year.
cat > ca.self <<- EOF
id=Self
ca_is_default=0
ca_type=INTERNAL:SELF
ca_internal_serial=1235
ca_internal_issue_time=946684800
EOF

# Set up a basic certificate.
cat > entry.openssl <<- EOF
id=Test
ca_name=Self
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile
autorenew=1
EOF

# Run through the whole enrollment process.
$toolsdir/iterate ca.self entry.openssl NEED_KEY_PAIR,GENERATING_KEY_PAIR,HAVE_KEY_PAIR
$toolsdir/iterate ca.self entry.openssl NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO,NEED_CSR
$toolsdir/iterate ca.self entry.openssl NEED_CSR,GENERATING_CSR,HAVE_CSR
$toolsdir/iterate ca.self entry.openssl NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca.self entry.openssl NEED_TO_SAVE_CERT,START_SAVING_CERT,SAVING_CERT
$toolsdir/iterate ca.self entry.openssl NEED_TO_SAVE_CA_CERTS,START_SAVING_CA_CERTS,SAVING_CA_CERTS
$toolsdir/iterate ca.self entry.openssl NEED_TO_READ_CERT,READING_CERT,SAVED_CERT
$toolsdir/iterate ca.self entry.openssl NEED_TO_NOTIFY_ISSUED_SAVED,NOTIFYING_ISSUED_SAVED

# Now kick it and see what we decide to do next.  Expect NEED_KEY_PAIR.
echo key_generated_date=20000101000000 >> entry.openssl
$toolsdir/iterate ca.self entry.openssl MONITORING

rm -f ca.self entry.openssl keyfile certfile



# Set a "maximum" key use count of 2.
echo '[Uses = 2.]'
cat > certmonger.conf << EOF
[defaults]
notification_method=STDERR
max_key_use_count=2
max_key_lifetime=100y
[selfsign]
validity_period=1y
EOF

# Issue on 2000-01-01 for one year.
cat > ca.self <<- EOF
id=Self
ca_is_default=0
ca_type=INTERNAL:SELF
ca_internal_serial=1235
ca_internal_issue_time=946684800
EOF

# Set up a basic certificate.
cat > entry.openssl <<- EOF
id=Test
ca_name=Self
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile
autorenew=1
EOF

# Run through the whole enrollment process.
$toolsdir/iterate ca.self entry.openssl NEED_KEY_PAIR,GENERATING_KEY_PAIR,HAVE_KEY_PAIR
$toolsdir/iterate ca.self entry.openssl NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO,NEED_CSR
$toolsdir/iterate ca.self entry.openssl NEED_CSR,GENERATING_CSR,HAVE_CSR
$toolsdir/iterate ca.self entry.openssl NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca.self entry.openssl NEED_TO_SAVE_CERT,START_SAVING_CERT,SAVING_CERT
$toolsdir/iterate ca.self entry.openssl NEED_TO_SAVE_CA_CERTS,START_SAVING_CA_CERTS,SAVING_CA_CERTS
$toolsdir/iterate ca.self entry.openssl NEED_TO_READ_CERT,READING_CERT,SAVED_CERT
$toolsdir/iterate ca.self entry.openssl NEED_TO_NOTIFY_ISSUED_SAVED,NOTIFYING_ISSUED_SAVED

# Now kick it and see what we decide to do next.  Expect NEED_CSR/HAVE_KEY_PAIR.
echo key_generated_date=20000101000000 >> entry.openssl
$toolsdir/iterate ca.self entry.openssl MONITORING

rm -f ca.self entry.openssl keyfile certfile


# Set a "maximum" key use count of 1.
echo '[Uses = 1.]'
cat > certmonger.conf << EOF
[defaults]
notification_method=STDERR
max_key_use_count=1
max_key_lifetime=100y
[selfsign]
validity_period=1y
EOF

# Issue on 2000-01-01 for one year.
cat > ca.self <<- EOF
id=Self
ca_is_default=0
ca_type=INTERNAL:SELF
ca_internal_serial=1235
ca_internal_issue_time=946684800
EOF

# Set up a basic certificate.
cat > entry.openssl <<- EOF
id=Test
ca_name=Self
key_storage_type=FILE
key_storage_location=$tmpdir/keyfile
cert_storage_type=FILE
cert_storage_location=$tmpdir/certfile
autorenew=1
EOF

# Run through the whole enrollment process.
$toolsdir/iterate ca.self entry.openssl NEED_KEY_PAIR,GENERATING_KEY_PAIR,HAVE_KEY_PAIR
$toolsdir/iterate ca.self entry.openssl NEED_KEYINFO,READING_KEYINFO,HAVE_KEYINFO,NEED_CSR
$toolsdir/iterate ca.self entry.openssl NEED_CSR,GENERATING_CSR,HAVE_CSR
$toolsdir/iterate ca.self entry.openssl NEED_TO_SUBMIT,SUBMITTING
$toolsdir/iterate ca.self entry.openssl NEED_TO_SAVE_CERT,START_SAVING_CERT,SAVING_CERT
$toolsdir/iterate ca.self entry.openssl NEED_TO_SAVE_CA_CERTS,START_SAVING_CA_CERTS,SAVING_CA_CERTS
$toolsdir/iterate ca.self entry.openssl NEED_TO_READ_CERT,READING_CERT,SAVED_CERT
$toolsdir/iterate ca.self entry.openssl NEED_TO_NOTIFY_ISSUED_SAVED,NOTIFYING_ISSUED_SAVED

# Now kick it and see what we decide to do next.  Expect NEED_KEY_PAIR.
echo key_generated_date=20000101000000 >> entry.openssl
$toolsdir/iterate ca.self entry.openssl MONITORING

rm -f ca.self entry.openssl keyfile certfile




echo Test complete.
