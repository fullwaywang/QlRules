/**
 * @name file-6713ca45e7757297381f4b4cdb9cf5e624a9ad36-file_check_mem
 * @id cpp/file/6713ca45e7757297381f4b4cdb9cf5e624a9ad36/file-check-mem
 * @description file-6713ca45e7757297381f4b4cdb9cf5e624a9ad36-src/funcs.c-file_check_mem CVE-2015-8865
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlevel_414, RelationalOperation target_4, ArrayExpr target_5) {
	exists(AssignExpr target_0 |
		target_0.getLValue() instanceof ValueFieldAccess
		and target_0.getRValue().(AddExpr).getAnOperand() instanceof Literal
		and target_0.getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vlevel_414
		and target_4.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_0.getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_0.getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_5.getArrayOffset().(VariableAccess).getLocation()))
}

predicate func_1(Parameter vms_414, ValueFieldAccess target_1) {
		target_1.getTarget().getName()="len"
		and target_1.getQualifier().(PointerFieldAccess).getTarget().getName()="c"
		and target_1.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_414
}

predicate func_3(Function func, AssignAddExpr target_3) {
		target_3.getLValue() instanceof ValueFieldAccess
		and target_3.getRValue() instanceof Literal
		and target_3.getEnclosingFunction() = func
}

predicate func_4(Parameter vms_414, Parameter vlevel_414, RelationalOperation target_4) {
		 (target_4 instanceof GEExpr or target_4 instanceof LEExpr)
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vlevel_414
		and target_4.getLesserOperand().(ValueFieldAccess).getTarget().getName()="len"
		and target_4.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c"
		and target_4.getLesserOperand().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_414
}

predicate func_5(Parameter vms_414, Parameter vlevel_414, ArrayExpr target_5) {
		target_5.getArrayBase().(ValueFieldAccess).getTarget().getName()="li"
		and target_5.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="c"
		and target_5.getArrayBase().(ValueFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vms_414
		and target_5.getArrayOffset().(VariableAccess).getTarget()=vlevel_414
}

from Function func, Parameter vms_414, Parameter vlevel_414, ValueFieldAccess target_1, AssignAddExpr target_3, RelationalOperation target_4, ArrayExpr target_5
where
not func_0(vlevel_414, target_4, target_5)
and func_1(vms_414, target_1)
and func_3(func, target_3)
and func_4(vms_414, vlevel_414, target_4)
and func_5(vms_414, vlevel_414, target_5)
and vms_414.getType().hasName("magic_set *")
and vlevel_414.getType().hasName("unsigned int")
and vms_414.getParentScope+() = func
and vlevel_414.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
