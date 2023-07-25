/**
 * @name opensc-9d294de90d1cc66956389856e60b6944b27b4817-tcos_decipher
 * @id cpp/opensc/9d294de90d1cc66956389856e60b6944b27b4817/tcos-decipher
 * @description opensc-9d294de90d1cc66956389856e60b6944b27b4817-src/libopensc/card-tcos.c-tcos_decipher CVE-2020-26572
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vcrgram_len_599, ExprStmt target_1, ExprStmt target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(SubExpr).getValue()="260"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vcrgram_len_599
		and target_0.getThen().(ReturnStmt).getExpr().(UnaryMinusExpr).getValue()="-1300"
		and (func.getEntryPoint().(BlockStmt).getStmt(19)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(19).getFollowingStmt()=target_0)
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getLocation()))
}

predicate func_1(Parameter vcrgram_len_599, ExprStmt target_1) {
		target_1.getExpr().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="lc"
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getLValue().(ValueFieldAccess).getTarget().getName()="datalen"
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vcrgram_len_599
		and target_1.getExpr().(AssignExpr).getRValue().(AssignExpr).getRValue().(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_2(Parameter vcrgram_len_599, ExprStmt target_2) {
		target_2.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_2.getExpr().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_2.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcrgram_len_599
}

from Function func, Parameter vcrgram_len_599, ExprStmt target_1, ExprStmt target_2
where
not func_0(vcrgram_len_599, target_1, target_2, func)
and func_1(vcrgram_len_599, target_1)
and func_2(vcrgram_len_599, target_2)
and vcrgram_len_599.getType().hasName("size_t")
and vcrgram_len_599.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
