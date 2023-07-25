/**
 * @name libxml2-1358d157d0bd83be1dfe356a69213df9fac0b539-parseAndPrintFile
 * @id cpp/libxml2/1358d157d0bd83be1dfe356a69213df9fac0b539/parseAndPrintFile
 * @description libxml2-1358d157d0bd83be1dfe356a69213df9fac0b539-xmllint.c-parseAndPrintFile CVE-2021-3516
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vctxt_2210, Variable voptions, FunctionCall target_0) {
		target_0.getTarget().hasName("xmlCtxtUseOptions")
		and not target_0.getTarget().hasName("htmlCtxtUseOptions")
		and target_0.getArgument(0).(VariableAccess).getTarget()=vctxt_2210
		and target_0.getArgument(1).(VariableAccess).getTarget()=voptions
}

from Function func, Variable vctxt_2210, Variable voptions, FunctionCall target_0
where
func_0(vctxt_2210, voptions, target_0)
and vctxt_2210.getType().hasName("htmlParserCtxtPtr")
and voptions.getType().hasName("int")
and vctxt_2210.(LocalVariable).getFunction() = func
and not voptions.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
