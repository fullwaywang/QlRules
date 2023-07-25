/**
 * @name curl-8ef147c43646e91-ftp_statemachine
 * @id cpp/curl/8ef147c43646e91/ftp-statemachine
 * @description curl-8ef147c43646e91-ftp_statemachine CVE-2021-22947
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vpp_2669) {
	exists(IfStmt target_0 |
		target_0.getCondition().(PointerFieldAccess).getTarget().getName()="cache_size"
		and target_0.getCondition().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpp_2669)
}

predicate func_1(Variable vsock_2666, Variable vftpcode_2667, Variable vpp_2669, Variable vnread_2671, Parameter vdata_2662) {
	exists(FunctionCall target_1 |
		target_1.getTarget().hasName("ftp_readresp")
		and target_1.getArgument(0).(VariableAccess).getTarget()=vdata_2662
		and target_1.getArgument(1).(VariableAccess).getTarget()=vsock_2666
		and target_1.getArgument(2).(VariableAccess).getTarget()=vpp_2669
		and target_1.getArgument(3).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vftpcode_2667
		and target_1.getArgument(4).(AddressOfExpr).getOperand().(VariableAccess).getTarget()=vnread_2671)
}

from Function func, Variable vsock_2666, Variable vftpcode_2667, Variable vpp_2669, Variable vnread_2671, Parameter vdata_2662
where
not func_0(vpp_2669)
and vpp_2669.getType().hasName("pingpong *")
and func_1(vsock_2666, vftpcode_2667, vpp_2669, vnread_2671, vdata_2662)
and vnread_2671.getType().hasName("size_t")
and vdata_2662.getType().hasName("Curl_easy *")
and vsock_2666.getParentScope+() = func
and vftpcode_2667.getParentScope+() = func
and vpp_2669.getParentScope+() = func
and vnread_2671.getParentScope+() = func
and vdata_2662.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
