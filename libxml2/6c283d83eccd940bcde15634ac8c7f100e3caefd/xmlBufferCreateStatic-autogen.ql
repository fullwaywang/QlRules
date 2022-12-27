/**
 * @name libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufferCreateStatic
 * @id cpp/libxml2/6c283d83eccd940bcde15634ac8c7f100e3caefd/xmlBufferCreateStatic
 * @description libxml2-6c283d83eccd940bcde15634ac8c7f100e3caefd-xmlBufferCreateStatic CVE-2022-29824
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vsize_7185, Function func) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vsize_7185
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(AddExpr).getValue()="4294967295"
		and target_0.getThen().(ReturnStmt).getExpr().(Literal).getValue()="0"
		and (func.getEntryPoint().(BlockStmt).getStmt(2)=target_0 or func.getEntryPoint().(BlockStmt).getStmt(2).getFollowingStmt()=target_0))
}

predicate func_1(Parameter vmem_7185, Parameter vsize_7185) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(VariableAccess).getTarget()=vsize_7185
		and target_1.getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=vmem_7185
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="0"
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen().(ReturnStmt).getExpr().(Literal).getValue()="0")
}

from Function func, Parameter vmem_7185, Parameter vsize_7185
where
not func_0(vsize_7185, func)
and vsize_7185.getType().hasName("size_t")
and func_1(vmem_7185, vsize_7185)
and vmem_7185.getParentScope+() = func
and vsize_7185.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
