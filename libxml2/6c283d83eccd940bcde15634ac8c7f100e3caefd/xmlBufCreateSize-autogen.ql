/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufCreateSize
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufCreateSize
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufCreateSize CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_151) {
	exists(Literal target_0 |
		target_0.getValue()="2"
		and not target_0.getValue()="1"
		and target_0.getParent().(AddExpr).getParent().(ConditionalExpr).getThen().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsize_151)
}

predicate func_1(Parameter vsize_151, Function func) {
	exists(IfStmt target_1 |
		target_1.getCondition().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vsize_151
		and target_1.getCondition().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="18446744073709551615"
		and target_1.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(1)=target_1 or func.getEntryPoint().(BlockStmt).getStmt(1).getFollowingStmt()=target_1))
}

from Function func, Parameter vsize_151
where
func_0(vsize_151)
and not func_1(vsize_151, func)
and vsize_151.getType().hasName("size_t")
and vsize_151.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
