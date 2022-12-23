/**
 * @name linux-abfaf0eee97925905e742aa3b0b72e04a918fa9e-kfd_parse_subtype_iolink
 * @id cpp/linux/abfaf0eee97925905e742aa3b0b72e04a918fa9e/kfd-parse-subtype-iolink
 * @description linux-abfaf0eee97925905e742aa3b0b72e04a918fa9e-kfd_parse_subtype_iolink 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vprops_1006, Variable vprops2_1006, Parameter violink_1003) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vprops2_1006
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-12"
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="12"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vprops_1006
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getTarget().getName()="flags"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=violink_1003
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getLeftOperand().(Literal).getValue()="1"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(BitwiseAndExpr).getRightOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="31")
}

predicate func_1(Variable vprops2_1006) {
	exists(PointerDereferenceExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vprops2_1006)
}

from Function func, Variable vprops_1006, Variable vprops2_1006, Parameter violink_1003
where
not func_0(vprops_1006, vprops2_1006, violink_1003)
and vprops_1006.getType().hasName("kfd_iolink_properties *")
and vprops2_1006.getType().hasName("kfd_iolink_properties *")
and func_1(vprops2_1006)
and violink_1003.getType().hasName("crat_subtype_iolink *")
and vprops_1006.getParentScope+() = func
and vprops2_1006.getParentScope+() = func
and violink_1003.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
