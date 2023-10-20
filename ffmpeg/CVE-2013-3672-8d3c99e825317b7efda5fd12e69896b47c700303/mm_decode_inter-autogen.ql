/**
 * @name ffmpeg-8d3c99e825317b7efda5fd12e69896b47c700303-mm_decode_inter
 * @id cpp/ffmpeg/8d3c99e825317b7efda5fd12e69896b47c700303/mm-decode-inter
 * @description ffmpeg-8d3c99e825317b7efda5fd12e69896b47c700303-libavcodec/mmvideo.c-mm_decode_inter CVE-2013-3672
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vs_127, Parameter vhalf_horiz_127, Variable vx_139, AddressOfExpr target_1, ExprStmt target_2, IfStmt target_3, ExprStmt target_4) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vx_139
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vhalf_horiz_127
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="avctx"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_127
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1094995529"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getCondition().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vs_127, AddressOfExpr target_1) {
		target_1.getOperand().(PointerFieldAccess).getTarget().getName()="gb"
		and target_1.getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_127
}

predicate func_2(Parameter vs_127, Variable vx_139, ExprStmt target_2) {
		target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_127
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getLeftOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="linesize"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(MulExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_2.getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vx_139
		and target_2.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_3(Parameter vhalf_horiz_127, Variable vx_139, IfStmt target_3) {
		target_3.getCondition().(VariableAccess).getTarget()=vhalf_horiz_127
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayBase().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vx_139
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(ArrayExpr).getArrayOffset().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_3.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget().getType().hasName("int")
}

predicate func_4(Variable vx_139, ExprStmt target_4) {
		target_4.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget().getType().hasName("int")
		and target_4.getExpr().(AssignAddExpr).getRValue().(VariableAccess).getTarget()=vx_139
}

from Function func, Parameter vs_127, Parameter vhalf_horiz_127, Variable vx_139, AddressOfExpr target_1, ExprStmt target_2, IfStmt target_3, ExprStmt target_4
where
not func_0(vs_127, vhalf_horiz_127, vx_139, target_1, target_2, target_3, target_4)
and func_1(vs_127, target_1)
and func_2(vs_127, vx_139, target_2)
and func_3(vhalf_horiz_127, vx_139, target_3)
and func_4(vx_139, target_4)
and vs_127.getType().hasName("MmContext *")
and vhalf_horiz_127.getType().hasName("int")
and vx_139.getType().hasName("int")
and vs_127.getFunction() = func
and vhalf_horiz_127.getFunction() = func
and vx_139.(LocalVariable).getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
