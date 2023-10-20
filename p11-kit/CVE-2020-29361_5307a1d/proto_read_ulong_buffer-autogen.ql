/**
 * @name p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-proto_read_ulong_buffer
 * @id cpp/p11-kit/5307a1d21a50cacd06f471a873a018d23ba4b963/proto-read-ulong-buffer
 * @description p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-p11-kit/rpc-server.c-proto_read_ulong_buffer CVE-2020-29361
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_168, Parameter vmsg_164, FunctionCall target_0) {
		target_0.getTarget().hasName("p11_rpc_message_alloc_extra")
		and not target_0.getTarget().hasName("p11_rpc_message_alloc_extra_array")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vmsg_164
		and target_0.getArgument(1).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vlength_168
		and target_0.getArgument(1).(MulExpr).getRightOperand() instanceof SizeofTypeOperator
}

predicate func_1(Variable vlength_168, VariableAccess target_1) {
		target_1.getTarget()=vlength_168
}

predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="8"
		and target_2.getEnclosingFunction() = func
}

from Function func, Variable vlength_168, Parameter vmsg_164, FunctionCall target_0, VariableAccess target_1, SizeofTypeOperator target_2
where
func_0(vlength_168, vmsg_164, target_0)
and func_1(vlength_168, target_1)
and func_2(func, target_2)
and vlength_168.getType().hasName("uint32_t")
and vmsg_164.getType().hasName("p11_rpc_message *")
and vlength_168.getParentScope+() = func
and vmsg_164.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
