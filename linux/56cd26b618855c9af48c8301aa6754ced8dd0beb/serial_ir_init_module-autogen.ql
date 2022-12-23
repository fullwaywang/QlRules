/**
 * @name linux-56cd26b618855c9af48c8301aa6754ced8dd0beb-serial_ir_init_module
 * @id cpp/linux/56cd26b618855c9af48c8301aa6754ced8dd0beb/serial-ir-init-module
 * @description linux-56cd26b618855c9af48c8301aa6754ced8dd0beb-serial_ir_init_module 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("serial_ir_init")
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Function func) {
	exists(DeclStmt target_1 |
		func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

predicate func_2(Variable vresult_776, Function func) {
	exists(ExprStmt target_2 |
		target_2.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vresult_776
		and target_2.getExpr().(AssignExpr).getRValue() instanceof FunctionCall
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_2)
}

predicate func_3(Variable vresult_776, Function func) {
	exists(IfStmt target_3 |
		target_3.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vresult_776
		and target_3.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_3)
}

predicate func_4(Function func) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("serial_ir_exit")
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4)
}

predicate func_5(Variable vresult_776) {
	exists(VariableAccess target_5 |
		target_5.getTarget()=vresult_776)
}

from Function func, Variable vresult_776
where
func_0(func)
and func_1(func)
and func_2(vresult_776, func)
and func_3(vresult_776, func)
and func_4(func)
and func_5(vresult_776)
and vresult_776.getType().hasName("int")
and vresult_776.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
