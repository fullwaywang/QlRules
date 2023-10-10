/**
 * @name linux-40413955ee265a5e42f710940ec78f5450d49149-cipso_v4_optptr
 * @id cpp/linux/40413955ee265a5e42f710940ec78f5450d49149/cipso-v4-optptr
 * @description linux-40413955ee265a5e42f710940ec78f5450d49149-cipso_v4_optptr 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vtaglen_1523) {
	exists(SwitchStmt target_0 |
		target_0.getExpr() instanceof ArrayExpr
		and target_0.getStmt().(BlockStmt).getStmt(0).(SwitchCase).getExpr() instanceof BitwiseOrExpr
		and target_0.getStmt().(BlockStmt).getStmt(1) instanceof ReturnStmt
		and target_0.getStmt().(BlockStmt).getStmt(2).(SwitchCase).getExpr().(BitwiseOrExpr).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(2).(SwitchCase).getExpr().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(2).(SwitchCase).getExpr().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(3) instanceof ReturnStmt
		and target_0.getStmt().(BlockStmt).getStmt(4).(SwitchCase).getExpr().(BitwiseOrExpr).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(4).(SwitchCase).getExpr().(BitwiseOrExpr).getLeftOperand().(Literal).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(4).(SwitchCase).getExpr().(BitwiseOrExpr).getRightOperand().(Literal).getValue()="0"
		and target_0.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtaglen_1523
		and target_0.getStmt().(BlockStmt).getStmt(5).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="1"
		and target_0.getStmt().(BlockStmt).getStmt(6).(BreakStmt).toString() = "break;"
		and target_0.getStmt().(BlockStmt).getStmt(7).(SwitchCase).toString() = "default: "
		and target_0.getStmt().(BlockStmt).getStmt(8) instanceof ExprStmt)
}

predicate func_7(Function func) {
	exists(LabelStmt target_7 |
		target_7.toString() = "label ...:"
		and target_7.getEnclosingFunction() = func)
}

predicate func_12(Variable voptptr_1521, Variable vtaglen_1523) {
	exists(ExprStmt target_12 |
		target_12.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vtaglen_1523
		and target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=voptptr_1521
		and target_12.getExpr().(AssignExpr).getRValue().(ArrayExpr).getArrayOffset().(Literal).getValue()="1")
}

predicate func_13(Function func) {
	exists(ReturnStmt target_13 |
		target_13.getExpr().(Literal).getValue()="0"
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_13)
}

predicate func_14(Function func) {
	exists(IfStmt target_14 |
		target_14.getCondition().(EqualityOperation).getAnOperand() instanceof ArrayExpr
		and target_14.getCondition().(EqualityOperation).getAnOperand() instanceof BitwiseOrExpr
		and target_14.getThen() instanceof ReturnStmt
		and target_14.getEnclosingFunction() = func)
}

from Function func, Variable voptptr_1521, Variable vtaglen_1523
where
not func_0(vtaglen_1523)
and not func_7(func)
and func_12(voptptr_1521, vtaglen_1523)
and func_13(func)
and func_14(func)
and voptptr_1521.getType().hasName("unsigned char *")
and vtaglen_1523.getType().hasName("int")
and voptptr_1521.getParentScope+() = func
and vtaglen_1523.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
