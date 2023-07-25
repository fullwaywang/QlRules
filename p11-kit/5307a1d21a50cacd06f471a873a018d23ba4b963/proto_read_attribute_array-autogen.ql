/**
 * @name p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-proto_read_attribute_array
 * @id cpp/p11-kit/5307a1d21a50cacd06f471a873a018d23ba4b963/proto-read-attribute-array
 * @description p11-kit-5307a1d21a50cacd06f471a873a018d23ba4b963-p11-kit/rpc-server.c-proto_read_attribute_array CVE-2020-29361
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vn_attrs_288, Parameter vmsg_283, FunctionCall target_0) {
		target_0.getTarget().hasName("p11_rpc_message_alloc_extra")
		and not target_0.getTarget().hasName("p11_rpc_message_alloc_extra_array")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vmsg_283
		and target_0.getArgument(1).(MulExpr).getLeftOperand().(VariableAccess).getTarget()=vn_attrs_288
		and target_0.getArgument(1).(MulExpr).getRightOperand() instanceof SizeofTypeOperator
}

predicate func_1(Variable vn_attrs_288, VariableAccess target_1) {
		target_1.getTarget()=vn_attrs_288
}

predicate func_2(Function func, SizeofTypeOperator target_2) {
		target_2.getType() instanceof LongType
		and target_2.getValue()="24"
		and target_2.getEnclosingFunction() = func
}

from Function func, Variable vn_attrs_288, Parameter vmsg_283, FunctionCall target_0, VariableAccess target_1, SizeofTypeOperator target_2
where
func_0(vn_attrs_288, vmsg_283, target_0)
and func_1(vn_attrs_288, target_1)
and func_2(func, target_2)
and vn_attrs_288.getType().hasName("uint32_t")
and vmsg_283.getType().hasName("p11_rpc_message *")
and vn_attrs_288.getParentScope+() = func
and vmsg_283.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
