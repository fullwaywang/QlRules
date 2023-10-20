/**
 * @name varnish-fcf5722af75fdbf58dd425dd68d0beaa49bab4f4-http_hdr_flags
 * @id cpp/varnish/fcf5722af75fdbf58dd425dd68d0beaa49bab4f4/http-hdr-flags
 * @description varnish-fcf5722af75fdbf58dd425dd68d0beaa49bab4f4-bin/varnishd/cache/cache_http.c-http_hdr_flags CVE-2022-45059
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vu_140, Literal target_0) {
		target_0.getValue()="3"
		and not target_0.getValue()="79"
		and target_0.getParent().(GTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vu_140
}

predicate func_1(Parameter vb_138, NotExpr target_5, Literal target_1) {
		target_1.getValue()="3"
		and not target_1.getValue()="0"
		and target_1.getParent().(ArrayExpr).getParent().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vb_138
		and target_1.getParent().(ArrayExpr).getParent().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_5.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_2(Variable vu_140, Literal target_2) {
		target_2.getValue()="38"
		and not target_2.getValue()="79"
		and target_2.getParent().(GTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vu_140
}

predicate func_3(Variable vu_140, Parameter vb_138, ExprStmt target_6, RelationalOperation target_7, NotExpr target_8, NotExpr target_5) {
	exists(AddExpr target_3 |
		target_3.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const unsigned char[256]")
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vb_138
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vu_140
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_3.getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getType().hasName("const unsigned char[256]")
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vb_138
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_3.getParent().(AssignAddExpr).getRValue() = target_3
		and target_3.getParent().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vu_140
		and target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getLocation())
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset().(SubExpr).getLeftOperand().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(VariableAccess).getLocation())
		and target_8.getOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_3.getAnOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getLocation())
		and target_3.getAnOperand().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_5.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Variable vu_140, Variable vhttp_asso_values, Parameter vb_138, Function func, IfStmt target_4) {
		target_4.getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vu_140
		and target_4.getCondition().(RelationalOperation).getLesserOperand() instanceof Literal
		and target_4.getThen().(ExprStmt).getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vu_140
		and target_4.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhttp_asso_values
		and target_4.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vb_138
		and target_4.getThen().(ExprStmt).getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset() instanceof Literal
		and func.getEntryPoint().(BlockStmt).getAStmt()=target_4
}

predicate func_5(Parameter vb_138, NotExpr target_5) {
		target_5.getOperand().(NotExpr).getOperand().(FunctionCall).getTarget().hasName("vct_caselencmp")
		and target_5.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(PointerFieldAccess).getTarget().getName()="hdr"
		and target_5.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(0).(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="1"
		and target_5.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vb_138
		and target_5.getOperand().(NotExpr).getOperand().(FunctionCall).getArgument(2).(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vb_138
}

predicate func_6(Variable vu_140, Variable vhttp_asso_values, Parameter vb_138, ExprStmt target_6) {
		target_6.getExpr().(AssignAddExpr).getLValue().(VariableAccess).getTarget()=vu_140
		and target_6.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vhttp_asso_values
		and target_6.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vb_138
		and target_6.getExpr().(AssignAddExpr).getRValue().(ArrayExpr).getArrayOffset().(ArrayExpr).getArrayOffset() instanceof Literal
}

predicate func_7(Variable vu_140, RelationalOperation target_7) {
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vu_140
		and target_7.getLesserOperand() instanceof Literal
}

predicate func_8(Variable vu_140, Parameter vb_138, NotExpr target_8) {
		target_8.getOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vb_138
		and target_8.getOperand().(EqualityOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vu_140
}

from Function func, Variable vu_140, Variable vhttp_asso_values, Parameter vb_138, Literal target_0, Literal target_1, Literal target_2, IfStmt target_4, NotExpr target_5, ExprStmt target_6, RelationalOperation target_7, NotExpr target_8
where
func_0(vu_140, target_0)
and func_1(vb_138, target_5, target_1)
and func_2(vu_140, target_2)
and not func_3(vu_140, vb_138, target_6, target_7, target_8, target_5)
and func_4(vu_140, vhttp_asso_values, vb_138, func, target_4)
and func_5(vb_138, target_5)
and func_6(vu_140, vhttp_asso_values, vb_138, target_6)
and func_7(vu_140, target_7)
and func_8(vu_140, vb_138, target_8)
and vu_140.getType().hasName("unsigned int")
and vhttp_asso_values.getType() instanceof ArrayType
and vb_138.getType().hasName("const char *")
and vu_140.getParentScope+() = func
and not vhttp_asso_values.getParentScope+() = func
and vb_138.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
