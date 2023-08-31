/**
 * @name postgresql-049e1e2edb06854d7cd9460c22516efaa165fbf8-make_modifytable
 * @id cpp/postgresql/049e1e2edb06854d7cd9460c22516efaa165fbf8/make-modifytable
 * @description postgresql-049e1e2edb06854d7cd9460c22516efaa165fbf8-src/backend/optimizer/plan/createplan.c-make_modifytable CVE-2021-32028
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, SizeofTypeOperator target_0) {
		target_0.getType() instanceof LongType
		and target_0.getValue()="232"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Function func, SizeofTypeOperator target_1) {
		target_1.getType() instanceof LongType
		and target_1.getValue()="232"
		and target_1.getEnclosingFunction() = func
}

predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="232"
		and target_2.getEnclosingFunction() = func
}

predicate func_3(Function func, SizeofTypeOperator target_3) {
		target_3.getType() instanceof LongType
		and target_3.getValue()="232"
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Variable vnode_6882, NotExpr target_6, ExprStmt target_7, ExprStmt target_8) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictCols"
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_6882
		and target_4.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(2)=target_4
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_5(Variable vnode_6882, NotExpr target_6, ExprStmt target_9, ExprStmt target_10) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictCols"
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_6882
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("extract_update_targetlist_colnos")
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_5.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_6882
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_5
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_6
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_5.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

predicate func_6(NotExpr target_6) {
		target_6.getOperand().(VariableAccess).getTarget().getType().hasName("OnConflictExpr *")
}

predicate func_7(Variable vnode_6882, ExprStmt target_7) {
		target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_7.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_6882
		and target_7.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_8(Variable vnode_6882, ExprStmt target_8) {
		target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictWhere"
		and target_8.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_6882
		and target_8.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_9(Variable vnode_6882, ExprStmt target_9) {
		target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_9.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_6882
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="onConflictSet"
		and target_9.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("OnConflictExpr *")
}

predicate func_10(Variable vnode_6882, ExprStmt target_10) {
		target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="onConflictWhere"
		and target_10.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vnode_6882
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="onConflictWhere"
		and target_10.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget().getType().hasName("OnConflictExpr *")
}

from Function func, Variable vnode_6882, SizeofTypeOperator target_0, SizeofTypeOperator target_1, SizeofTypeOperator target_2, SizeofTypeOperator target_3, NotExpr target_6, ExprStmt target_7, ExprStmt target_8, ExprStmt target_9, ExprStmt target_10
where
func_0(func, target_0)
and func_1(func, target_1)
and func_2(func, target_2)
and func_3(func, target_3)
and not func_4(vnode_6882, target_6, target_7, target_8)
and not func_5(vnode_6882, target_6, target_9, target_10)
and func_6(target_6)
and func_7(vnode_6882, target_7)
and func_8(vnode_6882, target_8)
and func_9(vnode_6882, target_9)
and func_10(vnode_6882, target_10)
and vnode_6882.getType().hasName("ModifyTable *")
and vnode_6882.(LocalVariable).getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
