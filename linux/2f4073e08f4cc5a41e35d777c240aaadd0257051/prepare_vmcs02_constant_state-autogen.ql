/**
 * @name linux-2f4073e08f4cc5a41e35d777c240aaadd0257051-prepare_vmcs02_constant_state
 * @id cpp/linux/2f4073e08f4cc5a41e35d777c240aaadd0257051/prepare-vmcs02-constant-state
 * @description linux-2f4073e08f4cc5a41e35d777c240aaadd0257051-prepare_vmcs02_constant_state CVE-2015-5307
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vvmx_2134, Function func) {
	exists(DeclStmt target_0 |
		target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getTarget().getName()="kvm"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="vcpu"
		and target_0.getDeclarationEntry(0).(VariableDeclarationEntry).getVariable().getInitializer().(Initializer).getExpr().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vvmx_2134
		and func.getEntryPoint().(BlockStmt).getStmt(0)=target_0)
}

predicate func_1(Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(FunctionCall).getTarget().hasName("kvm_notify_vmexit_enabled")
		and target_1.getCondition().(FunctionCall).getArgument(0).(VariableAccess).getType().hasName("kvm *")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("vmcs_write32")
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getTarget().getName()="notify_window"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="arch"
		and target_1.getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(1).(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getType().hasName("kvm *")
		and (func.getEntryPoint().(BlockStmt).getStmt(9)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(9).getFollowingStmt()=target_1))
}

from Function func, Parameter vvmx_2134
where
not func_0(vvmx_2134, func)
and not func_1(func)
and vvmx_2134.getType().hasName("vcpu_vmx *")
and vvmx_2134.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
