/**
 * @name imagemagick-dca8d5892331a61bdfa90589d12551b9926d215a-GetEXIFProperty
 * @id cpp/imagemagick/dca8d5892331a61bdfa90589d12551b9926d215a/GetEXIFProperty
 * @description imagemagick-dca8d5892331a61bdfa90589d12551b9926d215a-MagickCore/property.c-GetEXIFProperty CVE-2014-8716
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vlength_1148, Variable voffset_1349, RelationalOperation target_1, LogicalOrExpr target_2, RelationalOperation target_3, ExprStmt target_4, RelationalOperation target_5) {
	exists(IfStmt target_0 |
		target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=voffset_1349
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=voffset_1349
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_1148
		and target_0.getThen().(ContinueStmt).toString() = "continue;"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getElse().(BlockStmt).getStmt(2)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_1
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(VariableAccess).getLocation())
		and target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_0.getCondition().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation().isBefore(target_5.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(RelationalOperation target_1) {
		 (target_1 instanceof GEExpr or target_1 instanceof LEExpr)
		and target_1.getGreaterOperand().(Literal).getValue()="4"
}

predicate func_2(Variable vlength_1148, LogicalOrExpr target_2) {
		target_2.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_2.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vlength_1148
}

predicate func_3(Variable vlength_1148, Variable voffset_1349, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_1349
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vlength_1148
}

predicate func_4(Variable voffset_1349, ExprStmt target_4) {
		target_4.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=voffset_1349
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ReadPropertyLong")
		and target_4.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="8"
}

predicate func_5(Variable voffset_1349, RelationalOperation target_5) {
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=voffset_1349
		and target_5.getGreaterOperand().(VariableAccess).getTarget()=voffset_1349
}

from Function func, Variable vlength_1148, Variable voffset_1349, RelationalOperation target_1, LogicalOrExpr target_2, RelationalOperation target_3, ExprStmt target_4, RelationalOperation target_5
where
not func_0(vlength_1148, voffset_1349, target_1, target_2, target_3, target_4, target_5)
and func_1(target_1)
and func_2(vlength_1148, target_2)
and func_3(vlength_1148, voffset_1349, target_3)
and func_4(voffset_1349, target_4)
and func_5(voffset_1349, target_5)
and vlength_1148.getType().hasName("size_t")
and voffset_1349.getType().hasName("ssize_t")
and vlength_1148.getParentScope+() = func
and voffset_1349.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
