
#this makefile is for smart card sim setup and operation
#https://github.com/OpenSC/OpenSC/wiki/Smart-Card-Simulation

fetch:
	git clone https://github.com/arekinath/PivApplet
	git clone https://github.com/frankmorgner/vsmartcard.git
	git clone https://github.com/arekinath/jcardsim.git
	git clone https://github.com/martinpaljak/oracle_javacard_sdks.git

export JC_CLASSIC_HOME := $PWD/oracle_javacard_sdks/jc305u3_kit
export JAVA_HOME := /usr/lib/jvm/java-8-openjdk-amd64

build2:
	(cd jcardsim && mvn initialize && mvn clean install)
	javac -classpath ./jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar PivApplet/src/net/cooperi/pivapplet/*.java

build1:
	(cd vsmartcard/virtualsmartcard && autoreconf -vis && ./configure && sudo make install)

build: build1 build2

jcardsim_piv.cfg:
	echo com.licel.jcardsim.card.applet.0.AID=A000000308000010000100 > $@
	echo com.licel.jcardsim.card.applet.0.Class=net.cooperi.pivapplet.PivApplet >> $@
	echo com.licel.jcardsim.card.ATR=3B80800101 >> $@
	echo com.licel.jcardsim.vsmartcard.host=localhost >> $@
	echo com.licel.jcardsim.vsmartcard.port=35963 >> $@

run: jcardsim_piv.cfg
	pcsc_scan &
	/usr/lib/jvm/java-8-openjdk-amd64/bin/java -classpath './jcardsim/target/jcardsim-3.0.5-SNAPSHOT.jar:PivApplet/src:IsoApplet/src' com.licel.jcardsim.remote.VSmartCard ./jcardsim_piv.cfg

piv:
	opensc-tool --card-driver default --send-apdu 80b80000120ba000000308000010000100050000020F0F7f

