/**
 * @name linux-5d2be1422e02ccd697ccfcd45c85b4a26e6178e2-tipc_nl_compat_link_dump
 * @id cpp/linux/5d2be1422e02ccd697ccfcd45c85b4a26e6178e2/tipc-nl-compat-link-dump
 * @description linux-5d2be1422e02ccd697ccfcd45c85b4a26e6178e2-tipc_nl_compat_link_dump 
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("nla_strlcpy")
		and target_0.getArgument(0) instanceof ValueFieldAccess
		and target_0.getArgument(1) instanceof FunctionCall
		and target_0.getArgument(2).(Literal).getValue()="60"
		and target_0.getEnclosingFunction() = func)
}

predicate func_1(Variable vlink_info_594) {
	exists(ValueFieldAccess target_1 |
		target_1.getTarget().getName()="str"
		and target_1.getQualifier().(VariableAccess).getTarget()=vlink_info_594)
}

predicate func_2(Variable vlink_593) {
	exists(FunctionCall target_2 |
		target_2.getTarget().hasName("nla_data")
		and target_2.getArgument(0).(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vlink_593)
}

predicate func_3(Function func) {
	exists(FunctionCall target_3 |
		target_3.getTarget().hasName("strcpy")
		and target_3.getArgument(0) instanceof ValueFieldAccess
		and target_3.getArgument(1) instanceof FunctionCall
		and target_3.getEnclosingFunction() = func)
}

from Function func, Variable vlink_593, Variable vlink_info_594
where
not func_0(func)
and func_1(vlink_info_594)
and func_2(vlink_593)
and func_3(func)
and vlink_593.getType().hasName("nlattr *[11]")
and vlink_info_594.getType().hasName("tipc_link_info")
and vlink_593.getParentScope+() = func
and vlink_info_594.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
