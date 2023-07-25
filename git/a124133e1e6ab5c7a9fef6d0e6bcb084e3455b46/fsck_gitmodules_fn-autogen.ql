/**
 * @name git-a124133e1e6ab5c7a9fef6d0e6bcb084e3455b46-fsck_gitmodules_fn
 * @id cpp/git/a124133e1e6ab5c7a9fef6d0e6bcb084e3455b46/fsck-gitmodules-fn
 * @description git-a124133e1e6ab5c7a9fef6d0e6bcb084e3455b46-fsck.c-fsck_gitmodules_fn CVE-2018-17456
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvalue_931, Variable vdata_933, Variable vkey_934, ExprStmt target_1, AddressOfExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkey_934
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="url"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vvalue_931
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("looks_like_command_line_option")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_931
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ret"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_933
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="options"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_933
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="obj"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_933
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(3).(StringLiteral).getValue()="disallowed submodule url: %s"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_931
		and (func.getEntryPoint().(BlockStmt).getStmt(7)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(7).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Variable vdata_933, ExprStmt target_1) {
		target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ret"
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_933
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="options"
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_933
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="obj"
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_933
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(3).(StringLiteral).getValue()="disallowed submodule name: %s"
}

predicate func_2(Variable vkey_934, AddressOfExpr target_2) {
		target_2.getOperand().(VariableAccess).getTarget()=vkey_934
}

from Function func, Parameter vvalue_931, Variable vdata_933, Variable vkey_934, ExprStmt target_1, AddressOfExpr target_2
where
not func_0(vvalue_931, vdata_933, vkey_934, target_1, target_2, func)
and func_1(vdata_933, target_1)
and func_2(vkey_934, target_2)
and vvalue_931.getType().hasName("const char *")
and vdata_933.getType().hasName("fsck_gitmodules_data *")
and vkey_934.getType().hasName("const char *")
and vvalue_931.getParentScope+() = func
and vdata_933.getParentScope+() = func
and vkey_934.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
