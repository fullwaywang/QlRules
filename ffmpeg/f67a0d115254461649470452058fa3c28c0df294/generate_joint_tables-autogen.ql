/**
 * @name ffmpeg-f67a0d115254461649470452058fa3c28c0df294-generate_joint_tables
 * @id cpp/ffmpeg/f67a0d115254461649470452058fa3c28c0df294/generate-joint-tables
 * @description ffmpeg-f67a0d115254461649470452058fa3c28c0df294-libavcodec/huffyuvdec.c-generate_joint_tables CVE-2013-0868
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_140) {
	exists(DoStmt target_0 |
		target_0.getCondition() instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_140
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getValue()="2048"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="i < (1 << 11)"
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_0.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort"))
}

/*predicate func_1(Variable vi_140, RelationalOperation target_24) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_140
		and target_1.getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getValue()="2048"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="i < (1 << 11)"
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_1.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_1
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24)
}

*/
/*predicate func_2(Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_2.getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_2.getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_2.getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="i < (1 << 11)"
		and target_2.getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_2.getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_2.getEnclosingFunction() = func)
}

*/
/*predicate func_3(Function func) {
	exists(ExprStmt target_3 |
		target_3.getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_3.getEnclosingFunction() = func)
}

*/
predicate func_4(Variable vi_140, ExprStmt target_25, ExprStmt target_18) {
	exists(DoStmt target_4 |
		target_4.getCondition() instanceof Literal
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vi_140
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getGreaterOperand().(BinaryBitwiseOperation).getValue()="2048"
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_log")
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="Assertion %s failed at %s:%d\n"
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="i < (1 << 11)"
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof StringLiteral
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(5) instanceof Literal
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("abort")
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_4.getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(NotExpr).getOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_5(RelationalOperation target_24, Function func, DeclStmt target_5) {
		target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_5.getEnclosingFunction() = func
}

predicate func_6(RelationalOperation target_24, Function func, DeclStmt target_6) {
		target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_6.getEnclosingFunction() = func
}

predicate func_7(RelationalOperation target_24, Function func, DeclStmt target_7) {
		target_7.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_7.getEnclosingFunction() = func
}

predicate func_8(RelationalOperation target_24, Function func, DeclStmt target_8) {
		target_8.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
		and target_8.getEnclosingFunction() = func
}

predicate func_11(Variable vlimit0_148, IfStmt target_11) {
		target_11.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit0_148
		and target_11.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="2"
}

predicate func_14(Variable vlimit1_153, IfStmt target_14) {
		target_14.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit1_153
		and target_14.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="1"
}

predicate func_15(Parameter vs_110, Variable vb_140, Variable vg_140, Variable vcode_140, Variable vp0_141, Variable vp1_142, Variable vlen1_152, ExprStmt target_15) {
		target_15.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcode_140
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bits"
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vp0_141
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vg_140
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="255"
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vlen1_152
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bits"
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_110
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vp1_142
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vb_140
		and target_15.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="255"
}

predicate func_17(Variable vlimit1_153, Variable vlen2_158, IfStmt target_17) {
		target_17.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen2_158
		and target_17.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlimit1_153
}

predicate func_18(Variable vlen_114, Variable vi_140, Variable vlen0_147, Variable vlen1_152, Variable vlen2_158, ExprStmt target_18) {
		target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlen_114
		and target_18.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_140
		and target_18.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen0_147
		and target_18.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen1_152
		and target_18.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlen2_158
}

predicate func_19(Parameter vs_110, Variable vbits_113, Variable vi_140, Variable vr_140, Variable vcode_140, Variable vlen2_158, ExprStmt target_19) {
		target_19.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vbits_113
		and target_19.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_140
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget()=vcode_140
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(BinaryBitwiseOperation).getRightOperand().(VariableAccess).getTarget()=vlen2_158
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="bits"
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_110
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getLeftOperand().(VariableAccess).getTarget()=vr_140
		and target_19.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(ArrayExpr).getArrayOffset().(BitwiseAndExpr).getRightOperand().(Literal).getValue()="255"
}

predicate func_20(Parameter vs_110, Variable vmap_139, Variable vi_140, Variable vb_140, Variable vg_140, Variable vr_140, IfStmt target_20) {
		target_20.getCondition().(PointerFieldAccess).getTarget().getName()="decorrelate"
		and target_20.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_110
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmap_139
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_140
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_20.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vg_140
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmap_139
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_140
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vg_140
		and target_20.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb_140
		and target_20.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmap_139
		and target_20.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_140
		and target_20.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_20.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vg_140
		and target_20.getThen().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vr_140
		and target_20.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmap_139
		and target_20.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_140
		and target_20.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_20.getElse().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vg_140
		and target_20.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmap_139
		and target_20.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_140
		and target_20.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_20.getElse().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vb_140
		and target_20.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vmap_139
		and target_20.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vi_140
		and target_20.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="2"
		and target_20.getElse().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vr_140
}

predicate func_21(Variable vi_140, ExprStmt target_21) {
		target_21.getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vi_140
}

predicate func_22(Parameter vs_110, RelationalOperation target_24, ExprStmt target_22) {
		target_22.getExpr().(FunctionCall).getTarget().hasName("ff_free_vlc")
		and target_22.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="vlc"
		and target_22.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_110
		and target_22.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_22.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_23(Parameter vs_110, Variable vbits_113, Variable vlen_114, Variable vi_140, RelationalOperation target_24, ExprStmt target_23) {
		target_23.getExpr().(FunctionCall).getTarget().hasName("ff_init_vlc_sparse")
		and target_23.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="vlc"
		and target_23.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_110
		and target_23.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="3"
		and target_23.getExpr().(FunctionCall).getArgument(1).(Literal).getValue()="11"
		and target_23.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vi_140
		and target_23.getExpr().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vlen_114
		and target_23.getExpr().(FunctionCall).getArgument(4).(Literal).getValue()="1"
		and target_23.getExpr().(FunctionCall).getArgument(5).(Literal).getValue()="1"
		and target_23.getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vbits_113
		and target_23.getExpr().(FunctionCall).getArgument(7).(Literal).getValue()="2"
		and target_23.getExpr().(FunctionCall).getArgument(8).(Literal).getValue()="2"
		and target_23.getExpr().(FunctionCall).getArgument(9).(Literal).getValue()="0"
		and target_23.getExpr().(FunctionCall).getArgument(10).(Literal).getValue()="0"
		and target_23.getExpr().(FunctionCall).getArgument(11).(Literal).getValue()="0"
		and target_23.getExpr().(FunctionCall).getArgument(12).(Literal).getValue()="0"
		and target_23.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_24
}

predicate func_24(Parameter vs_110, RelationalOperation target_24) {
		 (target_24 instanceof GTExpr or target_24 instanceof LTExpr)
		and target_24.getLesserOperand().(PointerFieldAccess).getTarget().getName()="bitstream_bpp"
		and target_24.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_110
		and target_24.getGreaterOperand().(Literal).getValue()="24"
}

predicate func_25(Variable vi_140, Variable vg_140, ExprStmt target_25) {
		target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_140
		and target_25.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_25.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vg_140
		and target_25.getExpr().(CommaExpr).getRightOperand().(AssignExpr).getRValue().(UnaryMinusExpr).getValue()="-16"
}

from Function func, Parameter vs_110, Variable vbits_113, Variable vlen_114, Variable vmap_139, Variable vi_140, Variable vb_140, Variable vg_140, Variable vr_140, Variable vcode_140, Variable vp0_141, Variable vp1_142, Variable vlen0_147, Variable vlimit0_148, Variable vlen1_152, Variable vlimit1_153, Variable vlen2_158, DeclStmt target_5, DeclStmt target_6, DeclStmt target_7, DeclStmt target_8, IfStmt target_11, IfStmt target_14, ExprStmt target_15, IfStmt target_17, ExprStmt target_18, ExprStmt target_19, IfStmt target_20, ExprStmt target_21, ExprStmt target_22, ExprStmt target_23, RelationalOperation target_24, ExprStmt target_25
where
not func_0(vi_140)
and not func_4(vi_140, target_25, target_18)
and func_5(target_24, func, target_5)
and func_6(target_24, func, target_6)
and func_7(target_24, func, target_7)
and func_8(target_24, func, target_8)
and func_11(vlimit0_148, target_11)
and func_14(vlimit1_153, target_14)
and func_15(vs_110, vb_140, vg_140, vcode_140, vp0_141, vp1_142, vlen1_152, target_15)
and func_17(vlimit1_153, vlen2_158, target_17)
and func_18(vlen_114, vi_140, vlen0_147, vlen1_152, vlen2_158, target_18)
and func_19(vs_110, vbits_113, vi_140, vr_140, vcode_140, vlen2_158, target_19)
and func_20(vs_110, vmap_139, vi_140, vb_140, vg_140, vr_140, target_20)
and func_21(vi_140, target_21)
and func_22(vs_110, target_24, target_22)
and func_23(vs_110, vbits_113, vlen_114, vi_140, target_24, target_23)
and func_24(vs_110, target_24)
and func_25(vi_140, vg_140, target_25)
and vs_110.getType().hasName("HYuvContext *")
and vbits_113.getType().hasName("uint16_t[2048]")
and vlen_114.getType().hasName("uint8_t[2048]")
and vmap_139.getType().hasName("uint8_t(*)[4]")
and vi_140.getType().hasName("int")
and vb_140.getType().hasName("int")
and vg_140.getType().hasName("int")
and vr_140.getType().hasName("int")
and vcode_140.getType().hasName("int")
and vp0_141.getType().hasName("int")
and vp1_142.getType().hasName("int")
and vlen0_147.getType().hasName("int")
and vlimit0_148.getType().hasName("int")
and vlen1_152.getType().hasName("int")
and vlimit1_153.getType().hasName("int")
and vlen2_158.getType().hasName("int")
and vs_110.getFunction() = func
and vbits_113.(LocalVariable).getFunction() = func
and vlen_114.(LocalVariable).getFunction() = func
and vmap_139.(LocalVariable).getFunction() = func
and vi_140.(LocalVariable).getFunction() = func
and vb_140.(LocalVariable).getFunction() = func
and vg_140.(LocalVariable).getFunction() = func
and vr_140.(LocalVariable).getFunction() = func
and vcode_140.(LocalVariable).getFunction() = func
and vp0_141.(LocalVariable).getFunction() = func
and vp1_142.(LocalVariable).getFunction() = func
and vlen0_147.(LocalVariable).getFunction() = func
and vlimit0_148.(LocalVariable).getFunction() = func
and vlen1_152.(LocalVariable).getFunction() = func
and vlimit1_153.(LocalVariable).getFunction() = func
and vlen2_158.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
