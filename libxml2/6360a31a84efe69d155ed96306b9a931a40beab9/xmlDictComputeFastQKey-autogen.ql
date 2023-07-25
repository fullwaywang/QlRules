/**
 * @name libxml2-6360a31a84efe69d155ed96306b9a931a40beab9-xmlDictComputeFastQKey
 * @id cpp/libxml2/6360a31a84efe69d155ed96306b9a931a40beab9/xmlDictComputeFastQKey
 * @description libxml2-6360a31a84efe69d155ed96306b9a931a40beab9-dict.c-xmlDictComputeFastQKey CVE-2015-7497
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vlen_479, RelationalOperation target_3) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getType().hasName("int")
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getType().hasName("int")
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlen_479
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(SubExpr).getRightOperand().(AddExpr).getValue()="11"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(1)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_3)
}

predicate func_2(Parameter vplen_478, Parameter vlen_479, SubExpr target_2) {
		target_2.getLeftOperand().(VariableAccess).getTarget()=vlen_479
		and target_2.getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vplen_478
		and target_2.getRightOperand().(AddExpr).getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getRightOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_2.getParent().(ArrayExpr).getArrayBase().(VariableAccess).getTarget().getType().hasName("const xmlChar *")
}

predicate func_3(Parameter vlen_479, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(VariableAccess).getTarget()=vlen_479
		and target_3.getLesserOperand().(Literal).getValue()="10"
}

from Function func, Parameter vplen_478, Parameter vlen_479, SubExpr target_2, RelationalOperation target_3
where
not func_0(vlen_479, target_3)
and func_2(vplen_478, vlen_479, target_2)
and func_3(vlen_479, target_3)
and vplen_478.getType().hasName("int")
and vlen_479.getType().hasName("int")
and vplen_478.getFunction() = func
and vlen_479.getFunction() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
