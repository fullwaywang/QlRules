/**
 * @name libexpat-a2fe525e660badd64b6c557c2b1ec26ddc07f6e4-addBinding
 * @id cpp/libexpat/a2fe525e660badd64b6c557c2b1ec26ddc07f6e4/addBinding
 * @description libexpat-a2fe525e660badd64b6c557c2b1ec26ddc07f6e4-addBinding CVE-2022-25236
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vuri_3707, Parameter vparser_3706, Variable vlen_3732) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_ns"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3706
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vuri_3707
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(ArrayExpr).getArrayOffset().(VariableAccess).getTarget()=vlen_3732
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="m_namespaceSeparator"
		and target_0.getCondition().(LogicalAndExpr).getAnOperand().(EqualityOperation).getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparser_3706)
}

predicate func_2(Parameter vuri_3707, Variable vlen_3732) {
	exists(ArrayExpr target_2 |
		target_2.getArrayBase().(VariableAccess).getTarget()=vuri_3707
		and target_2.getArrayOffset().(VariableAccess).getTarget()=vlen_3732)
}

predicate func_3(Variable vxmlnsNamespace_3718, Variable vlen_3732) {
	exists(ArrayExpr target_3 |
		target_3.getArrayBase().(VariableAccess).getTarget()=vxmlnsNamespace_3718
		and target_3.getArrayOffset().(VariableAccess).getTarget()=vlen_3732)
}

from Function func, Parameter vuri_3707, Variable vxmlnsNamespace_3718, Parameter vparser_3706, Variable vlen_3732
where
not func_0(vuri_3707, vparser_3706, vlen_3732)
and vuri_3707.getType().hasName("const XML_Char *")
and func_2(vuri_3707, vlen_3732)
and vparser_3706.getType().hasName("XML_Parser")
and vlen_3732.getType().hasName("int")
and func_3(vxmlnsNamespace_3718, vlen_3732)
and vuri_3707.getParentScope+() = func
and vxmlnsNamespace_3718.getParentScope+() = func
and vparser_3706.getParentScope+() = func
and vlen_3732.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
