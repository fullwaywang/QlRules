/**
 * @name linux-973c096f6a85e5b5f2a295126ba6928d9a6afd45-vgacon_startup
 * @id cpp/linux/973c096f6a85e5b5f2a295126ba6928d9a6afd45/vgacon_startup
 * @description linux-973c096f6a85e5b5f2a295126ba6928d9a6afd45-vgacon_startup 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vvga_init_done) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vvga_init_done
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition() instanceof NotExpr)
}

predicate func_1(Variable vvga_init_done, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vvga_init_done
		and target_1.getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vgacon_scrollback_startup")
		and target_1.getThen().(BlockStmt).getStmt(1) instanceof ExprStmt
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_1)
}

from Function func, Variable vvga_init_done
where
func_0(vvga_init_done)
and func_1(vvga_init_done, func)
and vvga_init_done.getType().hasName("bool")
and not vvga_init_done.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
