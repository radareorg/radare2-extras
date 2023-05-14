#aui 44100
aui
f abs = 0x4000
f track0 = 0
f track1 = abs
aub abs

# (phone x y,s track0,auws $0,auo-,s track1,auws $1,auo_,s track0,aum track1,au.)
""(phone x y;auws $0@track0;auws $1@track1;s track0;aum track1;au.)
(tone x;s track0;auws $0;au.)

# .(tone 697)

""(1;.(phone 697 1209))
""(2;.(phone 697 1336))
""(3;.(phone 697 1477))
""(A;.(phone 697 1633))

""(4;.(phone 770 1209))
""(5;.(phone 770 1336))
""(6;.(phone 770 1477))
""(B;.(phone 770 1633))

""(7;.(phone 852 1209))
""(8;.(phone 852 1336))
""(9;.(phone 852 1477))
""(C;.(phone 852 1633))

""(*;.(phone 941 1209))
""(0;.(phone 941 1336))
""(#;.(phone 941 1477))
""(D;.(phone 941 1633))

# .(phone 697 1209)
# .(2);.(1);.(3);.(5);.(5);.(6);.(8)

# au.
# auws 660
# auo_ 400
# auwc 660 @ track1
# auwn 200 @ track1
# auo- @ track1
# aum track1
# au.
# 
# auws 660
# auo-
# # auo_ 400
# auws 660 @ track1
# auwn 200 @ track1
# # auo- @ track1
# aum track1
# au.

# telf tones

# ### 1 ###
# auws 697 @ track0
# auo- @ track0
# auws 1209 @ track1
# auo_ @ track1
# aum track1 @ track0
# au.
# 
# ### 2 ###
# auws 697 @ track0
# auo- @ track0
# auws 1336 @ track1
# auo_ @ track1
# aum track1 @ track0
# au.
# 
# ### 3 ###
# auws 697 @ track0
# auo- @ track0
# auws 1477 @ track1
# auo_ @ track1
# aum track1 @ track0
# au.
# 
# ### 4 ###
# auws 697 @ track0
# auo- @ track0
# auws 1633 @ track1
# auo_ @ track1
# aum track1 @ track0
# au.
# q

# auws 660; au.
# auws 510; au.
# auws 660; au.
# auws 770; au.
# auws 380; au.
