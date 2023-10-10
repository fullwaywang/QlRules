/**
 * @name git-0060fd1511b94c918928fa3708f69a3f33895a4a-module_clone
 * @id cpp/git/0060fd1511b94c918928fa3708f69a3f33895a4a/module-clone
 * @description git-0060fd1511b94c918928fa3708f69a3f33895a4a-builtin/submodule--helper.c-module_clone CVE-2019-1349
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_2(Variable vpath_623, NotExpr target_3, ExprStmt target_4, RelationalOperation target_5) {
	exists(IfStmt target_2 |
		target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(VariableAccess).getType().hasName("int")
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("access")
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_623
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(Literal).getValue()="1"
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("is_empty_dir")
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_623
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("die")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("_")
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(StringLiteral).getValue()="directory not empty: '%s'"
		and target_2.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vpath_623
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(0)=target_2
		and target_2.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation().isBefore(target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
		and target_2.getCondition().(LogicalAndExpr).getAnOperand().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation().isBefore(target_5.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getLocation()))
}

predicate func_3(NotExpr target_3) {
		target_3.getOperand().(FunctionCall).getTarget().hasName("file_exists")
}

predicate func_4(Variable vpath_623, ExprStmt target_4) {
		target_4.getExpr().(FunctionCall).getTarget().hasName("die")
		and target_4.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getTarget().hasName("_")
		and target_4.getExpr().(FunctionCall).getArgument(0).(FunctionCall).getArgument(0).(StringLiteral).getValue()="clone of '%s' into submodule path '%s' failed"
		and target_4.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vpath_623
}

predicate func_5(Variable vpath_623, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(FunctionCall).getTarget().hasName("safe_create_leading_directories_const")
		and target_5.getLesserOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vpath_623
		and target_5.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Variable vpath_623, NotExpr target_3, ExprStmt target_4, RelationalOperation target_5
where
not func_2(vpath_623, target_3, target_4, target_5)
and func_3(target_3)
and func_4(vpath_623, target_4)
and func_5(vpath_623, target_5)
and vpath_623.getType().hasName("char *")
and vpath_623.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
