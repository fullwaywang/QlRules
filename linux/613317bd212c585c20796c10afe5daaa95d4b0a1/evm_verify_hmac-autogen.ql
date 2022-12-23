/**
 * @name linux-613317bd212c585c20796c10afe5daaa95d4b0a1-evm_verify_hmac
 * @id cpp/linux/613317bd212c585c20796c10afe5daaa95d4b0a1/evm_verify_hmac
 * @description linux-613317bd212c585c20796c10afe5daaa95d4b0a1-evm_verify_hmac CVE-2016-2085
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vxattr_data_115, Variable vcalc_116) {
	exists(FunctionCall target_0 |
		target_0.getTarget().hasName("memcmp")
		and not target_0.getTarget().hasName("crypto_memneq")
		and target_0.getArgument(0).(PointerFieldAccess).getTarget().getName()="digest"
		and target_0.getArgument(0).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vxattr_data_115
		and target_0.getArgument(1).(ValueFieldAccess).getTarget().getName()="digest"
		and target_0.getArgument(1).(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcalc_116
		and target_0.getArgument(2).(SizeofExprOperator).getValue()="20"
		and target_0.getArgument(2).(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getTarget().getName()="digest"
		and target_0.getArgument(2).(SizeofExprOperator).getExprOperand().(ValueFieldAccess).getQualifier().(VariableAccess).getTarget()=vcalc_116)
}

from Function func, Variable vxattr_data_115, Variable vcalc_116
where
func_0(vxattr_data_115, vcalc_116)
and vxattr_data_115.getType().hasName("evm_ima_xattr_data *")
and vcalc_116.getType().hasName("evm_ima_xattr_data")
and vxattr_data_115.getParentScope+() = func
and vcalc_116.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
