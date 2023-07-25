/**
 * @name libsndfile-6d7ce94c020cc720a6b28719d1a7879181790008-wav_write_header
 * @id cpp/libsndfile/6d7ce94c020cc720a6b28719d1a7879181790008/wav-write-header
 * @description libsndfile-6d7ce94c020cc720a6b28719d1a7879181790008-src/wav.c-wav_write_header CVE-2019-3832
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Parameter vpsf_1055, EqualityOperation target_4, PointerFieldAccess target_5, RelationalOperation target_6) {
	exists(IfStmt target_0 |
		target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getTarget().getName()="loop_count"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="instrument"
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_1055
		and target_0.getCondition().(RelationalOperation).getLesserOperand().(DivExpr).getValue()="16"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getTarget().getName()="loop_count"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="instrument"
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_1055
		and target_0.getThen().(ExprStmt).getExpr().(AssignExpr).getRValue().(DivExpr).getValue()="16"
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getThen().(BlockStmt).getStmt(10)=target_0
		and target_0.getParent().(BlockStmt).getParent().(IfStmt).getCondition()=target_4
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation())
		and target_0.getCondition().(RelationalOperation).getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

/*predicate func_1(Parameter vpsf_1055, RelationalOperation target_6) {
	exists(AssignExpr target_1 |
		target_1.getLValue().(PointerFieldAccess).getTarget().getName()="loop_count"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="instrument"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_1055
		and target_1.getRValue().(DivExpr).getValue()="16"
		and target_1.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getLocation()))
}

*/
predicate func_2(Parameter vpsf_1055, PointerFieldAccess target_2) {
		target_2.getTarget().getName()="loop_count"
		and target_2.getQualifier().(PointerFieldAccess).getTarget().getName()="instrument"
		and target_2.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_1055
}

predicate func_3(Parameter vpsf_1055, AssignAndExpr target_3) {
		target_3.getLValue().(PointerFieldAccess).getTarget().getName()="loop_count"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="instrument"
		and target_3.getLValue().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_1055
		and target_3.getRValue().(HexLiteral).getValue()="32767"
}

predicate func_4(Parameter vpsf_1055, EqualityOperation target_4) {
		target_4.getAnOperand().(PointerFieldAccess).getTarget().getName()="instrument"
		and target_4.getAnOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_1055
		and target_4.getAnOperand().(Literal).getValue()="0"
}

predicate func_5(Parameter vpsf_1055, PointerFieldAccess target_5) {
		target_5.getTarget().getName()="loop_count"
		and target_5.getQualifier().(PointerFieldAccess).getTarget().getName()="instrument"
		and target_5.getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_1055
}

predicate func_6(Parameter vpsf_1055, RelationalOperation target_6) {
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getGreaterOperand().(PointerFieldAccess).getTarget().getName()="loop_count"
		and target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="instrument"
		and target_6.getGreaterOperand().(PointerFieldAccess).getQualifier().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vpsf_1055
}

from Function func, Parameter vpsf_1055, PointerFieldAccess target_2, AssignAndExpr target_3, EqualityOperation target_4, PointerFieldAccess target_5, RelationalOperation target_6
where
not func_0(vpsf_1055, target_4, target_5, target_6)
and func_2(vpsf_1055, target_2)
and func_3(vpsf_1055, target_3)
and func_4(vpsf_1055, target_4)
and func_5(vpsf_1055, target_5)
and func_6(vpsf_1055, target_6)
and vpsf_1055.getType().hasName("SF_PRIVATE *")
and vpsf_1055.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
