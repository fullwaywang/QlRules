/**
 * @name linux-5d6751eaff672ea77642e74e92e6c0ac7f9709ab-ath6kl_wmi_delete_pstream_cmd
 * @id cpp/linux/5d6751eaff672ea77642e74e92e6c0ac7f9709ab/ath6kl_wmi_delete_pstream_cmd
 * @description linux-5d6751eaff672ea77642e74e92e6c0ac7f9709ab-ath6kl_wmi_delete_pstream_cmd 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(Literal target_0 |
		target_0.getValue()="3"
		and not target_0.getValue()="4"
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getCondition() instanceof RelationalOperation
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Parameter vtraffic_class_2627) {
	exists(RelationalOperation target_1 |
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(VariableAccess).getTarget()=vtraffic_class_2627
		and target_1.getLesserOperand().(Literal).getValue()="4"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ath6kl_err")
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="invalid traffic class: %d\n"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtraffic_class_2627
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

predicate func_3(Parameter vtraffic_class_2627) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vtraffic_class_2627
		and target_3.getLesserOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ath6kl_err")
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(StringLiteral).getValue()="invalid traffic class: %d\n"
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vtraffic_class_2627
		and target_3.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(ReturnStmt).getExpr().(UnaryMinusExpr).getOperand().(Literal).getValue()="22")
}

from Function func, Parameter vtraffic_class_2627
where
func_0(func)
and not func_1(vtraffic_class_2627)
and func_3(vtraffic_class_2627)
and vtraffic_class_2627.getType().hasName("u8")
and vtraffic_class_2627.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
