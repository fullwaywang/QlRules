/**
 * @name ffmpeg-a581bb66ea5eb981e2e498ca301df7d1ef15a6a3-avi_write_trailer
 * @id cpp/ffmpeg/a581bb66ea5eb981e2e498ca301df7d1ef15a6a3/avi-write-trailer
 * @description ffmpeg-a581bb66ea5eb981e2e498ca301df7d1ef15a6a3-libavformat/avienc.c-avi_write_trailer CVE-2020-22039
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_1(Variable vj_912, Variable vavist_964, ForStmt target_1) {
		target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_912
		and target_1.getInitialization().(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_912
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(ValueFieldAccess).getTarget().getName()="ents_allocated"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="indexes"
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getLeftOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavist_964
		and target_1.getCondition().(RelationalOperation).getGreaterOperand().(DivExpr).getRightOperand().(Literal).getValue()="16384"
		and target_1.getUpdate().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vj_912
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("av_freep")
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getTarget().getName()="cluster"
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="indexes"
		and target_1.getStmt().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vj_912
}

predicate func_2(Variable vavist_964, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("av_freep")
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getTarget().getName()="cluster"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="indexes"
		and target_2.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavist_964
}

predicate func_3(Variable vavist_964, ExprStmt target_3) {
		target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="ents_allocated"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="indexes"
		and target_3.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavist_964
		and target_3.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="entry"
		and target_3.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="indexes"
		and target_3.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vavist_964
		and target_3.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(Literal).getValue()="0"
}

from Function func, Variable vj_912, Variable vavist_964, ForStmt target_1, ExprStmt target_2, ExprStmt target_3
where
func_1(vj_912, vavist_964, target_1)
and func_2(vavist_964, target_2)
and func_3(vavist_964, target_3)
and vj_912.getType().hasName("int")
and vavist_964.getType().hasName("AVIStream *")
and vj_912.getParentScope+() = func
and vavist_964.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
