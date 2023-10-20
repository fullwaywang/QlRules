/**
 * @name git-7c3745fc6185495d5765628b4dfe1bd2c25a2981-is_ntfs_dotgit
 * @id cpp/git/7c3745fc6185495d5765628b4dfe1bd2c25a2981/is-ntfs-dotgit
 * @description git-7c3745fc6185495d5765628b4dfe1bd2c25a2981-path.c-is_ntfs_dotgit CVE-2019-1352
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_1335, Parameter vname_1333, BlockStmt target_2, PostfixIncrExpr target_3, LogicalOrExpr target_1) {
	exists(LogicalOrExpr target_0 |
		target_0.getAnOperand() instanceof LogicalOrExpr
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vname_1333
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_1335
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="58"
		and target_0.getParent().(IfStmt).getThen()=target_2
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation())
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation().isBefore(target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlen_1335, Parameter vname_1333, BlockStmt target_2, LogicalOrExpr target_1) {
		target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vname_1333
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(NotExpr).getOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_1335
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vname_1333
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_1335
		and target_1.getAnOperand().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(CharLiteral).getValue()="92"
		and target_1.getAnOperand().(FunctionCall).getTarget().hasName("git_is_dir_sep")
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vname_1333
		and target_1.getAnOperand().(FunctionCall).getArgument(0).(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_1335
		and target_1.getParent().(IfStmt).getThen()=target_2
}

predicate func_2(Variable vlen_1335, Parameter vname_1333, BlockStmt target_2) {
		target_2.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getTarget().hasName("only_spaces_and_periods")
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_1333
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_1335
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("strncasecmp")
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vname_1333
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(StringLiteral).getValue()=".git"
		and target_2.getStmt(0).(IfStmt).getCondition().(LogicalAndExpr).getAnOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(Literal).getValue()="4"
		and target_2.getStmt(0).(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="1"
}

predicate func_3(Variable vlen_1335, PostfixIncrExpr target_3) {
		target_3.getOperand().(VariableAccess).getTarget()=vlen_1335
}

from Function func, Variable vlen_1335, Parameter vname_1333, LogicalOrExpr target_1, BlockStmt target_2, PostfixIncrExpr target_3
where
not func_0(vlen_1335, vname_1333, target_2, target_3, target_1)
and func_1(vlen_1335, vname_1333, target_2, target_1)
and func_2(vlen_1335, vname_1333, target_2)
and func_3(vlen_1335, target_3)
and vlen_1335.getType().hasName("size_t")
and vname_1333.getType().hasName("const char *")
and vlen_1335.getParentScope+() = func
and vname_1333.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
