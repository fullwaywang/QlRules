/**
 * @name linux-81f9c4e4177d31ced6f52a89bb70e93bfb77ca03-predicate_parse
 * @id cpp/linux/81f9c4e4177d31ced6f52a89bb70e93bfb77ca03/predicate-parse
 * @description linux-81f9c4e4177d31ced6f52a89bb70e93bfb77ca03-predicate_parse 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vstr_421, Parameter vpe_423, Variable vptr_427, Variable vret_432, Variable vN_434, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vN_434
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_432
		and target_0.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(UnaryMinusExpr).getOperand().(Literal).getValue()="22"
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("parse_error")
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpe_423
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vptr_427
		and target_0.getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_421
		and target_0.getThen().(BlockStmt).getStmt(2).(GotoStmt).toString() = "goto ..."
		and (func.getEntryPoint().(BlockStmt).getStmt(24)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(24).getFollowingStmt()=target_0))
}

predicate func_4(Parameter vstr_421, Parameter vpe_423, Variable vptr_427) {
	exists(PointerArithmeticOperation target_4 |
		target_4.getLeftOperand().(VariableAccess).getTarget()=vptr_427
		and target_4.getRightOperand().(VariableAccess).getTarget()=vstr_421
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("parse_error")
		and target_4.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpe_423)
}

predicate func_5(Parameter vstr_421, Parameter vpe_423, Variable vptr_427) {
	exists(FunctionCall target_5 |
		target_5.getTarget().hasName("parse_error")
		and target_5.getArgument(0).(VariableAccess).getTarget()=vpe_423
		and target_5.getArgument(2).(PointerArithmeticOperation).getLeftOperand().(VariableAccess).getTarget()=vptr_427
		and target_5.getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vstr_421)
}

predicate func_7(Variable vprog_426, Variable vinvert_431, Variable vN_434) {
	exists(SubExpr target_7 |
		target_7.getLeftOperand().(VariableAccess).getTarget()=vN_434
		and target_7.getRightOperand().(Literal).getValue()="1"
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("update_preds")
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vprog_426
		and target_7.getParent().(FunctionCall).getParent().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(NotExpr).getOperand().(VariableAccess).getTarget()=vinvert_431)
}

from Function func, Parameter vstr_421, Parameter vpe_423, Variable vprog_426, Variable vptr_427, Variable vinvert_431, Variable vret_432, Variable vN_434
where
not func_0(vstr_421, vpe_423, vptr_427, vret_432, vN_434, func)
and vstr_421.getType().hasName("const char *")
and func_4(vstr_421, vpe_423, vptr_427)
and vpe_423.getType().hasName("filter_parse_error *")
and func_5(vstr_421, vpe_423, vptr_427)
and vptr_427.getType().hasName("const char *")
and vret_432.getType().hasName("int")
and vN_434.getType().hasName("int")
and func_7(vprog_426, vinvert_431, vN_434)
and vstr_421.getParentScope+() = func
and vpe_423.getParentScope+() = func
and vprog_426.getParentScope+() = func
and vptr_427.getParentScope+() = func
and vinvert_431.getParentScope+() = func
and vret_432.getParentScope+() = func
and vN_434.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
