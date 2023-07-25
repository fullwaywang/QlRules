/**
 * @name git-1a7fd1fb2998002da6e9ff2ee46e1bdd25ee8404-fsck_gitmodules_fn
 * @id cpp/git/1a7fd1fb2998002da6e9ff2ee46e1bdd25ee8404/fsck-gitmodules-fn
 * @description git-1a7fd1fb2998002da6e9ff2ee46e1bdd25ee8404-fsck.c-fsck_gitmodules_fn CVE-2018-17456
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvalue_932, Variable vdata_934, Variable vkey_935, ExprStmt target_1, LogicalAndExpr target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkey_935
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="path"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vvalue_932
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("looks_like_command_line_option")
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_932
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ret"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_934
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="options"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_934
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="obj"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_934
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(3).(StringLiteral).getValue()="disallowed submodule path: %s"
		and target_0.getThen().(ExprStmt).getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_932
		and (func.getEntryPoint().(BlockStmt).getStmt(8)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(8).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getLocation())
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vvalue_932, Variable vdata_934, ExprStmt target_1) {
		target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getTarget().getName()="ret"
		and target_1.getExpr().(AssignOrExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_934
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getTarget().hasName("report")
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="options"
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_934
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getTarget().getName()="obj"
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(1).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vdata_934
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(3).(StringLiteral).getValue()="disallowed submodule url: %s"
		and target_1.getExpr().(AssignOrExpr).getRValue().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vvalue_932
}

predicate func_2(Parameter vvalue_932, Variable vkey_935, LogicalAndExpr target_2) {
		target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strcmp")
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkey_935
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()="url"
		and target_2.getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getTarget()=vvalue_932
		and target_2.getAnOperand().(FunctionCall).getTarget().hasName("looks_like_command_line_option")
		and target_2.getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vvalue_932
}

from Function func, Parameter vvalue_932, Variable vdata_934, Variable vkey_935, ExprStmt target_1, LogicalAndExpr target_2
where
not func_0(vvalue_932, vdata_934, vkey_935, target_1, target_2, func)
and func_1(vvalue_932, vdata_934, target_1)
and func_2(vvalue_932, vkey_935, target_2)
and vvalue_932.getType().hasName("const char *")
and vdata_934.getType().hasName("fsck_gitmodules_data *")
and vkey_935.getType().hasName("const char *")
and vvalue_932.getParentScope+() = func
and vdata_934.getParentScope+() = func
and vkey_935.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
