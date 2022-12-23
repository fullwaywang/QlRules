/**
 * @name linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_set_host_param
 * @id cpp/linux/ec98ea7070e94cc25a422ec97d1421e28d97b7ee/iscsi_set_host_param
 * @description linux-ec98ea7070e94cc25a422ec97d1421e28d97b7ee-iscsi_set_host_param 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Parameter vev_3024, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getTarget().getName()="len"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="set_host_param"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="u"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vev_3024
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getValue()="4096"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="12"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-22"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and (func.getEntryPoint().(BlockStmt).getStmt(4)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(4).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vev_3024) {
	exists(PointerDereferenceExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vev_3024)
}

from Function func, Parameter vev_3024
where
not func_0(vev_3024, func)
and vev_3024.getType().hasName("iscsi_uevent *")
and func_1(vev_3024)
and vev_3024.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
