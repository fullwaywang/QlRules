/**
 * @name jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_decode_symbol_dict
 * @id cpp/jbig2dec/e698d5c11d27212aa1098bc5b1673a3378563092/jbig2-decode-symbol-dict
 * @description jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_symbol_dict.c-jbig2_decode_symbol_dict CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_9(Variable vj_704, Variable vexrunlength_708, LogicalOrExpr target_16) {
	exists(AddExpr target_9 |
		target_9.getAnOperand().(VariableAccess).getTarget()=vexrunlength_708
		and target_9.getAnOperand().(VariableAccess).getTarget()=vj_704
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation().isBefore(target_9.getAnOperand().(VariableAccess).getLocation()))
}

predicate func_10(Parameter vparams_228, PointerFieldAccess target_10) {
		target_10.getTarget().getName()="SDNUMEXSYMS"
		and target_10.getQualifier().(VariableAccess).getTarget()=vparams_228
}

predicate func_13(Variable vexrunlength_708, RelationalOperation target_17, VariableAccess target_13) {
		target_13.getTarget()=vexrunlength_708
		and target_13.getLocation().isBefore(target_17.getLesserOperand().(VariableAccess).getLocation())
}

predicate func_14(Parameter vparams_228, Variable vj_704, SubExpr target_14) {
		target_14.getLeftOperand().(PointerFieldAccess).getTarget().getName()="SDNUMEXSYMS"
		and target_14.getLeftOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_228
		and target_14.getRightOperand().(VariableAccess).getTarget()=vj_704
}

predicate func_16(Variable vexrunlength_708, LogicalOrExpr target_16) {
		target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vexrunlength_708
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vexrunlength_708
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_16.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vexrunlength_708
		and target_16.getAnOperand().(LogicalAndExpr).getAnOperand().(RelationalOperation).getLesserOperand() instanceof SubExpr
}

predicate func_17(Variable vexrunlength_708, RelationalOperation target_17) {
		 (target_17 instanceof GEExpr or target_17 instanceof LEExpr)
		and target_17.getLesserOperand().(VariableAccess).getTarget()=vexrunlength_708
		and target_17.getGreaterOperand().(Literal).getValue()="0"
}

from Function func, Parameter vparams_228, Variable vj_704, Variable vexrunlength_708, PointerFieldAccess target_10, VariableAccess target_13, SubExpr target_14, LogicalOrExpr target_16, RelationalOperation target_17
where
not func_9(vj_704, vexrunlength_708, target_16)
and func_10(vparams_228, target_10)
and func_13(vexrunlength_708, target_17, target_13)
and func_14(vparams_228, vj_704, target_14)
and func_16(vexrunlength_708, target_16)
and func_17(vexrunlength_708, target_17)
and vparams_228.getType().hasName("const Jbig2SymbolDictParams *")
and vj_704.getType().hasName("int")
and vexrunlength_708.getType().hasName("int32_t")
and vparams_228.getParentScope+() = func
and vj_704.getParentScope+() = func
and vexrunlength_708.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
