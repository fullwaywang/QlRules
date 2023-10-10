/**
 * @name jbig2dec-9d2c4f3bdb0bd003deae788e7187c0f86e624544-jbig2_decode_symbol_dict
 * @id cpp/jbig2dec/9d2c4f3bdb0bd003deae788e7187c0f86e624544/jbig2-decode-symbol-dict
 * @description jbig2dec-9d2c4f3bdb0bd003deae788e7187c0f86e624544-jbig2_symbol_dict.c-jbig2_decode_symbol_dict CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vi_704, Variable vlimit_708, Variable vexrunlength_709, Variable vcode_250, LogicalOrExpr target_0) {
		target_0.getAnOperand().(VariableAccess).getTarget()=vcode_250
		and target_0.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vexrunlength_709
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vlimit_708
		and target_0.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(VariableAccess).getTarget()=vi_704
}

predicate func_1(Variable vj_705, Variable vexflag_707, Variable vexrunlength_709, Variable vzerolength_710, Parameter vparams_228, BlockStmt target_6, LogicalAndExpr target_1) {
		target_1.getAnOperand().(VariableAccess).getTarget()=vexflag_707
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vexrunlength_709
		and target_1.getAnOperand().(RelationalOperation).getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vj_705
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getTarget().getName()="SDNUMEXSYMS"
		and target_1.getAnOperand().(RelationalOperation).getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_228
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vzerolength_710
		and target_1.getParent().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_1.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_6
}

predicate func_2(Variable vcode_250, BlockStmt target_7, VariableAccess target_2) {
		target_2.getTarget()=vcode_250
		and target_2.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_2.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_3(Variable vBMSIZE_612, Variable vcode_250, BlockStmt target_7, RelationalOperation target_3) {
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(VariableAccess).getTarget()=vBMSIZE_612
		and target_3.getGreaterOperand().(Literal).getValue()="0"
		and target_3.getParent().(LogicalOrExpr).getAnOperand().(VariableAccess).getTarget()=vcode_250
		and target_3.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_7
}

predicate func_4(Variable vexrunlength_709, Variable vzerolength_710, BlockStmt target_6, LogicalOrExpr target_4) {
		target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand() instanceof LogicalOrExpr
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vexrunlength_709
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vzerolength_710
		and target_4.getAnOperand().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="4"
		and target_4.getAnOperand() instanceof LogicalAndExpr
		and target_4.getParent().(IfStmt).getThen()=target_6
}

/*predicate func_5(Variable vexrunlength_709, LogicalOrExpr target_5) {
		target_5.getAnOperand() instanceof LogicalOrExpr
		and target_5.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vexrunlength_709
		and target_5.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
}

*/
predicate func_6(Variable vj_705, Variable vexrunlength_709, Parameter vparams_228, Variable vcode_250, BlockStmt target_6) {
		target_6.getStmt(0).(IfStmt).getCondition().(VariableAccess).getTarget()=vcode_250
		and target_6.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_error")
		and target_6.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="number"
		and target_6.getStmt(0).(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="failed to decode exrunlength for exported symbols"
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vexrunlength_709
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getCondition().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_error")
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="number"
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="runlength too small in export symbol table (%d <= 0)\n"
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getThen().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vexrunlength_709
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_error")
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="number"
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="runlength too large in export symbol table (%d > %d - %d)\n"
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vexrunlength_709
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getTarget().getName()="SDNUMEXSYMS"
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(5).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vparams_228
		and target_6.getStmt(0).(IfStmt).getElse().(IfStmt).getElse().(ExprStmt).getExpr().(FunctionCall).getArgument(6).(VariableAccess).getTarget()=vj_705
}

predicate func_7(BlockStmt target_7) {
		target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("jbig2_error")
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="number"
		and target_7.getStmt(0).(ExprStmt).getExpr().(FunctionCall).getArgument(3).(StringLiteral).getValue()="error decoding size of collective bitmap!"
		and target_7.getStmt(1).(GotoStmt).toString() = "goto ..."
		and target_7.getStmt(1).(GotoStmt).getName() ="cleanup4"
}

from Function func, Variable vBMSIZE_612, Variable vi_704, Variable vj_705, Variable vexflag_707, Variable vlimit_708, Variable vexrunlength_709, Variable vzerolength_710, Parameter vparams_228, Variable vcode_250, LogicalOrExpr target_0, LogicalAndExpr target_1, VariableAccess target_2, RelationalOperation target_3, LogicalOrExpr target_4, BlockStmt target_6, BlockStmt target_7
where
func_0(vi_704, vlimit_708, vexrunlength_709, vcode_250, target_0)
and func_1(vj_705, vexflag_707, vexrunlength_709, vzerolength_710, vparams_228, target_6, target_1)
and func_2(vcode_250, target_7, target_2)
and func_3(vBMSIZE_612, vcode_250, target_7, target_3)
and func_4(vexrunlength_709, vzerolength_710, target_6, target_4)
and func_6(vj_705, vexrunlength_709, vparams_228, vcode_250, target_6)
and func_7(target_7)
and vBMSIZE_612.getType().hasName("uint32_t")
and vi_704.getType().hasName("uint32_t")
and vj_705.getType().hasName("uint32_t")
and vexflag_707.getType().hasName("int")
and vlimit_708.getType().hasName("uint32_t")
and vexrunlength_709.getType().hasName("uint32_t")
and vzerolength_710.getType().hasName("int")
and vparams_228.getType().hasName("const Jbig2SymbolDictParams *")
and vcode_250.getType().hasName("int")
and vBMSIZE_612.getParentScope+() = func
and vi_704.getParentScope+() = func
and vj_705.getParentScope+() = func
and vexflag_707.getParentScope+() = func
and vlimit_708.getParentScope+() = func
and vexrunlength_709.getParentScope+() = func
and vzerolength_710.getParentScope+() = func
and vparams_228.getParentScope+() = func
and vcode_250.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
