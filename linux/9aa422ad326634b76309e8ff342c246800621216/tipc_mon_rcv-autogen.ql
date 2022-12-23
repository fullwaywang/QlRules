/**
 * @name linux-9aa422ad326634b76309e8ff342c246800621216-tipc_mon_rcv
 * @id cpp/linux/9aa422ad326634b76309e8ff342c246800621216/tipc_mon_rcv
 * @description linux-9aa422ad326634b76309e8ff342c246800621216-tipc_mon_rcv CVE-2022-0435
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vnew_member_cnt_488, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vnew_member_cnt_488
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(Literal).getValue()="64"
		and target_0.getThen().(ReturnStmt).toString() = "return ..."
		and func.getEntryPoint().(BlockStmt).getStmt(13)=target_0)
}

predicate func_1(Variable varrv_dom_484, Variable vnew_member_cnt_488) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("dom_rec_len")
		and target_1.getArgument(0).(VariableAccess).getTarget()=varrv_dom_484
		and target_1.getArgument(1).(VariableAccess).getTarget()=vnew_member_cnt_488)
}

from Function func, Variable varrv_dom_484, Variable vnew_member_cnt_488
where
not func_0(vnew_member_cnt_488, func)
and vnew_member_cnt_488.getType().hasName("u16")
and func_1(varrv_dom_484, vnew_member_cnt_488)
and varrv_dom_484.getParentScope+() = func
and vnew_member_cnt_488.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
