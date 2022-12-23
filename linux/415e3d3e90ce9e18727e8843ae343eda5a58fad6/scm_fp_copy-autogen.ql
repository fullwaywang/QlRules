/**
 * @name linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-scm_fp_copy
 * @id cpp/linux/415e3d3e90ce9e18727e8843ae343eda5a58fad6/scm_fp_copy
 * @description linux-415e3d3e90ce9e18727e8843ae343eda5a58fad6-scm_fp_copy 
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(SizeofTypeOperator target_0 |
		target_0.getType() instanceof LongType
		and target_0.getValue()="2032"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vfpl_70) {
	exists(ExprStmt target_1 |
		target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_1.getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfpl_70
		and target_1.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
		and target_1.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(NotExpr).getOperand().(VariableAccess).getTarget()=vfpl_70)
}

predicate func_2(Variable vfpl_70, Function func) {
	exists(IfStmt target_2 |
		target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getTarget().getName()="user"
		and target_2.getCondition().(NotExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfpl_70
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="user"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vfpl_70
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("get_uid")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getTarget().getName()="user"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getCondition() instanceof Literal
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(0).(DeclStmt).getDeclarationEntry(0).(VariableDeclarationEntry).getType() instanceof CTypedefType
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("debug_lockdep_rcu_enabled")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(VariableAccess).getType().hasName("bool")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(Literal).getValue()="1"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("bool")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("lockdep_rcu_suspicious")
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof StringLiteral
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(0).(DoStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(BlockStmt).getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(StringLiteral).getValue()="suspicious rcu_dereference_protected() usage"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(1).(EmptyStmt).toString() = ";"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerFieldAccess).getTarget().getName()="cred"
		and target_2.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(StmtExpr).getStmt().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(StmtExpr).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PointerFieldAccess).getQualifier().(FunctionCall).getTarget().hasName("get_current")
		and (func.getEntryPoint().(BlockStmt).getStmt(11)=target_2 or func.getEntryPoint().(BlockStmt).getStmt(11).getFollowingStmt()=target_2))
}

predicate func_11(Variable vfpl_70) {
	exists(PointerFieldAccess target_11 |
		target_11.getTarget().getName()="max"
		and target_11.getQualifier().(VariableAccess).getTarget()=vfpl_70)
}

predicate func_12(Variable vfpl_70) {
	exists(PointerFieldAccess target_12 |
		target_12.getTarget().getName()="count"
		and target_12.getQualifier().(VariableAccess).getTarget()=vfpl_70)
}

from Function func, Variable vfpl_70
where
func_0(func)
and not func_1(vfpl_70)
and not func_2(vfpl_70, func)
and vfpl_70.getType().hasName("scm_fp_list *")
and func_11(vfpl_70)
and func_12(vfpl_70)
and vfpl_70.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
