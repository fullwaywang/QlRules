/**
 * @name ffmpeg-529a25d6e5c3ff889257a57042872d84dc2312d5-dpcm_decode_frame
 * @id cpp/ffmpeg/529a25d6e5c3ff889257a57042872d84dc2312d5/dpcm-decode-frame
 * @description ffmpeg-529a25d6e5c3ff889257a57042872d84dc2312d5-libavcodec/dpcm.c-dpcm_decode_frame CVE-2012-0854
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_179, RelationalOperation target_2, ExprStmt target_3) {
	exists(ArrayExpr target_0 |
		target_0.getArrayBase().(ValueFieldAccess).getTarget().getName()="data"
		and target_0.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="frame"
		and target_0.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_179
		and target_0.getArrayOffset().(Literal).getValue()="0"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_3.getExpr().(AssignAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vdata_173, ExprStmt target_4, VariableAccess target_1) {
		target_1.getTarget()=vdata_173
		and target_1.getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getLocation())
}

predicate func_2(Variable vs_179, RelationalOperation target_2) {
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(VariableAccess).getTarget().getType().hasName("int")
		and target_2.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="channels"
		and target_2.getGreaterOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_179
}

predicate func_3(Variable vs_179, ExprStmt target_3) {
		target_3.getExpr().(AssignAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sample"
		and target_3.getExpr().(AssignAddExpr).getLValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_179
		and target_3.getExpr().(AssignAddExpr).getLValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="sol_table"
		and target_3.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_179
		and target_3.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getLeftOperand().(VariableAccess).getTarget().getType().hasName("uint8_t")
		and target_3.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="4"
}

predicate func_4(Variable vs_179, Parameter vdata_173, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vdata_173
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="frame"
		and target_4.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vs_179
}

from Function func, Variable vs_179, Parameter vdata_173, VariableAccess target_1, RelationalOperation target_2, ExprStmt target_3, ExprStmt target_4
where
not func_0(vs_179, target_2, target_3)
and func_1(vdata_173, target_4, target_1)
and func_2(vs_179, target_2)
and func_3(vs_179, target_3)
and func_4(vs_179, vdata_173, target_4)
and vs_179.getType().hasName("DPCMContext *")
and vdata_173.getType().hasName("void *")
and vs_179.(LocalVariable).getFunction() = func
and vdata_173.getFunction() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
