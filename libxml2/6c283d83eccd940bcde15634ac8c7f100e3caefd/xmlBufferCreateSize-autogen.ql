/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufferCreateSize
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufferCreateSize
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufferCreateSize CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_7120) {
	exists(Literal target_0 |
		target_0.getValue()="2"
		and not target_0.getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_7120)
}

predicate func_1(Parameter vsize_7120, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7120
		and target_1.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="4294967295"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_1))
}

from Function func, Parameter vsize_7120
where
func_0(vsize_7120)
and not func_1(vsize_7120, func)
and vsize_7120.getType().hasName("size_t")
and vsize_7120.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
