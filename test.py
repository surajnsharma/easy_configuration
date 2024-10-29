<?xml version="1.0" encoding="UTF-8"?>
<op-script xmlns="http://xml.juniper.net/junos/slax/1.0">
    <script>
        <var name="start-interface" select="48"/>
        <var name="end-interface" select="96"/>

        <!-- Loop through interfaces xe-0/0/0 to xe-0/0/47 -->
        <for select="$start-interface to $end-interface" var="i">
            <var name="mapped-interface" select="$i - 48"/> <!-- Map ge-0/0/48 to ge-1/0/0, ge-0/0/96 to ge-1/0/47 -->

            <!-- Display the interfaces -->
            <trace>
                <message>
                    Interface ge-0/0/<value-of select="$i"/> is mapped to ge-1/0/<value-of select="$mapped-interface"/>
                </message>
            </trace>
        </for>
    </script>
</op-script>
