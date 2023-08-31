/**
 * @name postgresql-37a795a60-domain_state_setup
 * @id cpp/postgresql/37a795a60/domain-state-setup
 * @description postgresql-37a795a60-src/backend/utils/adt/domains.c-domain_state_setup CVE-2017-15098
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vdomainType_73, Literal target_0) {
		target_0.getValue()="0"
		and not target_0.getValue()="4096"
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("lookup_type_cache")
		and target_0.getParent().(FunctionCall).getParent().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vdomainType_73
}

predicate func_1(Variable vtypentry_76) {
	exists(PointerFieldAccess target_1 |
		target_1.getTarget().getName()="domainBaseType"
		and target_1.getQualifier().(VariableAccess).getTarget()=vtypentry_76)
}

predicate func_2(Variable vtypentry_76, EqualityOperation target_5) {
	exists(PointerFieldAccess target_2 |
		target_2.getTarget().getName()="domainBaseTypmod"
		and target_2.getQualifier().(VariableAccess).getTarget()=vtypentry_76
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_2.getQualifier().(VariableAccess).getLocation()))
}

predicate func_3(Variable vmy_extra_75, UnaryMinusExpr target_3) {
		target_3.getValue()="-1"
		and target_3.getParent().(AssignExpr).getRValue() = target_3
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="typtypmod"
		and target_3.getParent().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmy_extra_75
}

predicate func_4(Variable vmy_extra_75, Parameter vdomainType_73, FunctionCall target_4) {
		target_4.getTarget().hasName("getBaseTypeAndTypmod")
		and target_4.getArgument(0).(VariableAccess).getTarget()=vdomainType_73
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="typtypmod"
		and target_4.getArgument(1).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmy_extra_75
		and target_4.getParent().(AssignExpr).getRValue() = target_4
		and target_4.getParent().(AssignExpr).getLValue().(VariableAccess).getTarget().getType().hasName("Oid")
}

predicate func_5(Variable vtypentry_76, EqualityOperation target_5) {
		target_5.getAnOperand().(PointerFieldAccess).getTarget().getName()="typtype"
		and target_5.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vtypentry_76
		and target_5.getAnOperand().(Literal).getValue()="100"
}

from Function func, Variable vmy_extra_75, Variable vtypentry_76, Parameter vdomainType_73, Literal target_0, UnaryMinusExpr target_3, FunctionCall target_4, EqualityOperation target_5
where
func_0(vdomainType_73, target_0)
and not func_1(vtypentry_76)
and not func_2(vtypentry_76, target_5)
and func_3(vmy_extra_75, target_3)
and func_4(vmy_extra_75, vdomainType_73, target_4)
and func_5(vtypentry_76, target_5)
and vmy_extra_75.getType().hasName("DomainIOData *")
and vtypentry_76.getType().hasName("TypeCacheEntry *")
and vdomainType_73.getType().hasName("Oid")
and vmy_extra_75.(LocalVariable).getFunction() = func
and vtypentry_76.(LocalVariable).getFunction() = func
and vdomainType_73.getFunction() = func
select func, "function relativepath is " + func.getFile(), "function startline is " + func.getLocation().getStartLine()
