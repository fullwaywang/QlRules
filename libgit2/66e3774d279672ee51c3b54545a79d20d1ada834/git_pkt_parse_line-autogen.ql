/**
 * @name libgit2-66e3774d279672ee51c3b54545a79d20d1ada834-git_pkt_parse_line
 * @id cpp/libgit2/66e3774d279672ee51c3b54545a79d20d1ada834/git-pkt-parse-line
 * @description libgit2-66e3774d279672ee51c3b54545a79d20d1ada834-src/transports/smart_pkt.c-git_pkt_parse_line CVE-2016-10128
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlen_402, LogicalAndExpr target_1, EqualityOperation target_2, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vlen_402
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlen_402
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="4"
		and (func.getEntryPoint().(BlockStmt).getStmt(6)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(6).getFollowingStmt()=target_0)
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_2.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vlen_402, LogicalAndExpr target_1) {
		target_1.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="0"
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vlen_402
}

predicate func_2(Variable vlen_402, EqualityOperation target_2) {
		target_2.getAnOperand().(VariableAccess).getTarget()=vlen_402
		and target_2.getAnOperand().(Literal).getValue()="4"
}

from Function func, Variable vlen_402, LogicalAndExpr target_1, EqualityOperation target_2
where
not func_0(vlen_402, target_1, target_2, func)
and func_1(vlen_402, target_1)
and func_2(vlen_402, target_2)
and vlen_402.getType().hasName("int32_t")
and vlen_402.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
