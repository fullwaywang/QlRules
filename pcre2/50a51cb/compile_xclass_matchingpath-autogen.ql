/**
 * @name pcre2-50a51cb7e67268e6ad417eb07c9de9bfea5cc55a-compile_xclass_matchingpath
 * @id cpp/pcre2/50a51cb7e67268e6ad417eb07c9de9bfea5cc55a/compile-xclass-matchingpath
 * @description pcre2-50a51cb7e67268e6ad417eb07c9de9bfea5cc55a-compile_xclass_matchingpath CVE-2022-1586
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable v_pcre2_ucd_caseless_sets_8, Variable vmax_7437, Variable vmin_7437, Variable vother_cases_7448, Parameter vcc_7432) {
	exists(LogicalAndExpr target_0 |
		target_0.getAnOperand() instanceof EqualityOperation
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcc_7432
		and target_0.getAnOperand().(EqualityOperation).getAnOperand().(Literal).getValue()="3"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vother_cases_7448
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=v_pcre2_ucd_caseless_sets_8
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcc_7432
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4294967295"
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmax_7437
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_7437
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmin_7437
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmin_7437
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_0.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448)
}

predicate func_1(Variable v_pcre2_ucd_caseless_sets_8, Variable vmax_7437, Variable vmin_7437, Variable vother_cases_7448, Parameter vcc_7432) {
	exists(EqualityOperation target_1 |
		target_1.getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vcc_7432
		and target_1.getAnOperand().(Literal).getValue()="10"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vother_cases_7448
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=v_pcre2_ucd_caseless_sets_8
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vcc_7432
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerArithmeticOperation).getAnOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getCondition().(EqualityOperation).getAnOperand().(Literal).getValue()="4294967295"
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vmax_7437
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmax_7437
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vmin_7437
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vmin_7437
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(1).(IfStmt).getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448
		and target_1.getParent().(IfStmt).getThen().(BlockStmt).getStmt(1).(WhileStmt).getStmt().(BlockStmt).getStmt(2).(ExprStmt).getExpr().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vother_cases_7448)
}

predicate func_2(Parameter vcc_7432) {
	exists(PostfixIncrExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vcc_7432)
}

from Function func, Variable v_pcre2_ucd_caseless_sets_8, Variable vmax_7437, Variable vmin_7437, Variable vother_cases_7448, Parameter vcc_7432
where
not func_0(v_pcre2_ucd_caseless_sets_8, vmax_7437, vmin_7437, vother_cases_7448, vcc_7432)
and func_1(v_pcre2_ucd_caseless_sets_8, vmax_7437, vmin_7437, vother_cases_7448, vcc_7432)
and v_pcre2_ucd_caseless_sets_8.getType().hasName("const uint32_t[]")
and vmax_7437.getType().hasName("sljit_uw")
and vmin_7437.getType().hasName("sljit_uw")
and vother_cases_7448.getType().hasName("const sljit_u32 *")
and vcc_7432.getType().hasName("PCRE2_SPTR8")
and func_2(vcc_7432)
and not v_pcre2_ucd_caseless_sets_8.getParentScope+() = func
and vmax_7437.getParentScope+() = func
and vmin_7437.getParentScope+() = func
and vother_cases_7448.getParentScope+() = func
and vcc_7432.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
