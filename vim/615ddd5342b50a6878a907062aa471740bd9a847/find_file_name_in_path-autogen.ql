/**
 * @name vim-615ddd5342b50a6878a907062aa471740bd9a847-find_file_name_in_path
 * @id cpp/vim/615ddd5342b50a6878a907062aa471740bd9a847/find-file-name-in-path
 * @description vim-615ddd5342b50a6878a907062aa471740bd9a847-src/findfile.c-find_file_name_in_path CVE-2021-3973
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_2112, ExprStmt target_1, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_2112
		and target_0.getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(3)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(3).getFollowingStmt()=target_0)
		and target_0.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vlen_2112, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("eval_includeexpr")
		and target_1.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vlen_2112
}

from Function func, Parameter vlen_2112, ExprStmt target_1
where
not func_0(vlen_2112, target_1, func)
and func_1(vlen_2112, target_1)
and vlen_2112.getType().hasName("int")
and vlen_2112.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
