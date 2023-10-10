/**
 * @name linux-b4a1b4f5047e4f54e194681125c74c0aa64d637d-keyctl_read_key
 * @id cpp/linux/b4a1b4f5047e4f54e194681125c74c0aa64d637d/keyctl_read_key
 * @description linux-b4a1b4f5047e4f54e194681125c74c0aa64d637d-keyctl_read_key CVE-2015-7550
 * @kind problem
 * @tags security
 */

import cpp

predicate func_0(Variable vkey_723, Variable vret_725, Function func) {
	exists(ExprStmt target_0 |
		target_0.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_725
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("key_validate")
		and target_0.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vkey_723
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_0)
}

predicate func_4(Variable vkey_723) {
	exists(ExprStmt target_4 |
		target_4.getExpr().(FunctionCall).getTarget().hasName("down_read")
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sem"
		and target_4.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_723
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="read"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="type"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_4.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_723)
}

predicate func_5(Parameter vbuffer_721, Parameter vbuflen_721, Variable vkey_723, Variable vret_725) {
	exists(ExprStmt target_5 |
		target_5.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vret_725
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getTarget().getName()="read"
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="type"
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getExpr().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_723
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(0).(VariableAccess).getTarget()=vkey_723
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(1).(VariableAccess).getTarget()=vbuffer_721
		and target_5.getExpr().(AssignExpr).getRValue().(VariableCall).getArgument(2).(VariableAccess).getTarget()=vbuflen_721
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="read"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="type"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_5.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_723)
}

predicate func_6(Variable vkey_723) {
	exists(ExprStmt target_6 |
		target_6.getExpr().(FunctionCall).getTarget().hasName("up_read")
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getTarget().getName()="sem"
		and target_6.getExpr().(FunctionCall).getArgument(0).(AddressOfExpr).getOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_723
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getTarget().getName()="read"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="type"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getTarget().getName()="(unknown field)"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="(unknown field)"
		and target_6.getParent().(BlockStmt).getParent().(IfStmt).getCondition().(PointerFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vkey_723)
}

from Function func, Parameter vbuffer_721, Parameter vbuflen_721, Variable vkey_723, Variable vret_725
where
func_0(vkey_723, vret_725, func)
and func_4(vkey_723)
and func_5(vbuffer_721, vbuflen_721, vkey_723, vret_725)
and func_6(vkey_723)
and vbuffer_721.getType().hasName("char *")
and vbuflen_721.getType().hasName("size_t")
and vkey_723.getType().hasName("key *")
and vret_725.getType().hasName("long")
and vbuffer_721.getParentScope+() = func
and vbuflen_721.getParentScope+() = func
and vkey_723.getParentScope+() = func
and vret_725.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
