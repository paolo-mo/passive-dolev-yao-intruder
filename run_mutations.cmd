@echo off
set PROTOCOLS=Carlsen,WooLam,AndrewSecureRPC,Otway_Rees,NSPK,DenningSacco,Goss,KeyEx3,BKE,DH,Basic_Kerberos,Kerberos_PKINIT,SET_Orig,SET_Rev,Rev_1KP,Rev_3KP,WooLamMutual,KeyEx5,ISO5pass,H530

echo === N=1 pipeline ===
python run_test.py --protocols %PROTOCOLS% --sessions 1 --provider JDK --csv timing_n1.csv --log-suffix n1

echo === N=1 mutations ===
python mutate_and_verify.py --protocols %PROTOCOLS% --sessions 1 --verbose --csv mutations_n1.csv

echo === N=2 pipeline ===
python run_test.py --protocols %PROTOCOLS% --sessions 2 --provider JDK --csv timing_n2.csv --log-suffix n2

echo === N=2 mutations ===
python mutate_and_verify.py --protocols %PROTOCOLS% --sessions 2 --verbose --csv mutations_n2.csv