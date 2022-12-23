/**
 * @name linux-35d2969ea3c7d32aee78066b1f3cf61a0d935a4e-fdtv_ca_pmt
 * @id cpp/linux/35d2969ea3c7d32aee78066b1f3cf61a0d935a4e/fdtv-ca-pmt
 * @description linux-35d2969ea3c7d32aee78066b1f3cf61a0d935a4e-fdtv_ca_pmt 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vmsg_124, Variable vdata_pos_125, Variable vdata_length_126, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vdata_length_126
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getValue()="256"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getTarget().getName()="msg"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(SizeofExprOperator).getExprOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_124
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vdata_pos_125
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0))
}

predicate func_1(Variable vmsg_124) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="msg"
		and target_1.getQualifier().(VariableAccess).getTarget()=vmsg_124)
}

predicate func_2(Variable vmsg_124, Variable vdata_pos_125) {
	exists(PostfixIncrExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vdata_pos_125
		and target_2.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="msg"
		and target_2.getParent().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_124)
}

predicate func_3(Variable vmsg_124, Variable vdata_length_126) {
	exists(AssignExpr target_3 |
		target_3.getLValue().(VariableAccess).getTarget()=vdata_length_126
		and target_3.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getTarget().getName()="msg"
		and target_3.getRValue().(ArrayExpr).getArrayBase().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmsg_124
		and target_3.getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="3")
}

from Function func, Variable vmsg_124, Variable vdata_pos_125, Variable vdata_length_126
where
not func_0(vmsg_124, vdata_pos_125, vdata_length_126, func)
and vmsg_124.getType().hasName("ca_msg *")
and func_1(vmsg_124)
and vdata_pos_125.getType().hasName("int")
and func_2(vmsg_124, vdata_pos_125)
and vdata_length_126.getType().hasName("int")
and func_3(vmsg_124, vdata_length_126)
and vmsg_124.getParentScope+() = func
and vdata_pos_125.getParentScope+() = func
and vdata_length_126.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
