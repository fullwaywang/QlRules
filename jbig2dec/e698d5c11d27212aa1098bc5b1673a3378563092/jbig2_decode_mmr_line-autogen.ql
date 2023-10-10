/**
 * @name jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_decode_mmr_line
 * @id cpp/jbig2dec/e698d5c11d27212aa1098bc5b1673a3378563092/jbig2-decode-mmr-line
 * @description jbig2dec-e698d5c11d27212aa1098bc5b1673a3378563092-jbig2_mmr.c-jbig2_decode_mmr_line CVE-2016-9601
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Function func, UnaryMinusExpr target_0) {
		target_0.getValue()="-1"
		and target_0.getEnclosingFunction() = func
}

predicate func_1(Variable va0_1_834, ExprStmt target_49, UnaryMinusExpr target_1) {
		target_1.getValue()="-1"
		and target_1.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_1.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_49
}

predicate func_6(Function func, Literal target_6) {
		target_6.getValue()="0"
		and not target_6.getValue()="1"
		and target_6.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_6.getEnclosingFunction() = func
}

predicate func_7(Function func, Literal target_7) {
		target_7.getValue()="0"
		and not target_7.getValue()="1"
		and target_7.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_7.getEnclosingFunction() = func
}

predicate func_8(Function func, Literal target_8) {
		target_8.getValue()="0"
		and not target_8.getValue()="1"
		and target_8.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_8.getEnclosingFunction() = func
}

predicate func_9(Function func, Literal target_9) {
		target_9.getValue()="0"
		and not target_9.getValue()="1"
		and target_9.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_9.getEnclosingFunction() = func
}

predicate func_10(Function func, Literal target_10) {
		target_10.getValue()="0"
		and not target_10.getValue()="1"
		and target_10.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_10.getEnclosingFunction() = func
}

predicate func_11(Function func, Literal target_11) {
		target_11.getValue()="0"
		and not target_11.getValue()="1"
		and target_11.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_11.getEnclosingFunction() = func
}

predicate func_12(Function func, Literal target_12) {
		target_12.getValue()="0"
		and not target_12.getValue()="1"
		and target_12.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof SubExpr
		and target_12.getEnclosingFunction() = func
}

predicate func_13(Function func, Literal target_13) {
		target_13.getValue()="0"
		and not target_13.getValue()="1"
		and target_13.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_13.getEnclosingFunction() = func
}

predicate func_14(Function func, Literal target_14) {
		target_14.getValue()="0"
		and not target_14.getValue()="1"
		and target_14.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof SubExpr
		and target_14.getEnclosingFunction() = func
}

predicate func_15(Function func, Literal target_15) {
		target_15.getValue()="0"
		and not target_15.getValue()="1"
		and target_15.getParent().(LTExpr).getParent().(IfStmt).getCondition().(RelationalOperation).getLesserOperand() instanceof SubExpr
		and target_15.getEnclosingFunction() = func
}

predicate func_16(Function func, Literal target_16) {
		target_16.getValue()="0"
		and not target_16.getValue()="2"
		and target_16.getParent().(LTExpr).getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_16.getEnclosingFunction() = func
}

predicate func_18(Variable va0_1_834, BreakStmt target_50, RelationalOperation target_34) {
	exists(LogicalAndExpr target_18 |
		target_18.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_18.getAnOperand().(EqualityOperation).getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_18.getAnOperand() instanceof RelationalOperation
		and target_18.getParent().(IfStmt).getThen()=target_50
		and target_18.getAnOperand().(EqualityOperation).getAnOperand().(VariableAccess).getLocation().isBefore(target_34.getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_20(Variable va0_1_834, ExprStmt target_49) {
	exists(UnaryMinusExpr target_20 |
		target_20.getValue()="4294967295"
		and target_20.getParent().(EQExpr).getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_20.getParent().(EQExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_20.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_49)
}

predicate func_21(Variable va1_835, ReturnStmt target_51, ExprStmt target_52, LogicalOrExpr target_53) {
	exists(EqualityOperation target_21 |
		target_21.getAnOperand().(VariableAccess).getTarget()=va1_835
		and target_21.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_21.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va1_835
		and target_21.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_21.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_51
		and target_52.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_21.getAnOperand().(VariableAccess).getLocation())
		and target_21.getAnOperand().(VariableAccess).getLocation().isBefore(target_53.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_22(Variable va0_1_834, Variable va1_835, ReturnStmt target_54, ExprStmt target_55, LogicalOrExpr target_56) {
	exists(EqualityOperation target_22 |
		target_22.getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_22.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_22.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=va1_835
		and target_22.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_22.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_22.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_54
		and target_55.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_22.getAnOperand().(VariableAccess).getLocation())
		and target_22.getAnOperand().(VariableAccess).getLocation().isBefore(target_56.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_23(Variable va0_1_834, ReturnStmt target_57, ExprStmt target_58, LogicalOrExpr target_59) {
	exists(EqualityOperation target_23 |
		target_23.getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_23.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_23.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_23.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_23.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_57
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_23.getAnOperand().(VariableAccess).getLocation())
		and target_23.getAnOperand().(VariableAccess).getLocation().isBefore(target_59.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_24(Variable va0_1_834, Variable vb1_835, ReturnStmt target_60, ExprStmt target_61, LogicalOrExpr target_62) {
	exists(EqualityOperation target_24 |
		target_24.getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_24.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_24.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vb1_835
		and target_24.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_24.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_24.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_60
		and target_61.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_24.getAnOperand().(VariableAccess).getLocation())
		and target_24.getAnOperand().(VariableAccess).getLocation().isBefore(target_62.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_25(Variable va0_1_834, Variable vb1_835, ReturnStmt target_63, ExprStmt target_64, LogicalOrExpr target_65) {
	exists(EqualityOperation target_25 |
		target_25.getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_25.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_25.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb1_835
		and target_25.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_25.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_25.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_25.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_63
		and target_64.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_25.getAnOperand().(VariableAccess).getLocation())
		and target_25.getAnOperand().(VariableAccess).getLocation().isBefore(target_65.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_26(Variable va0_1_834, Variable vb1_835, ReturnStmt target_66, ExprStmt target_67, LogicalOrExpr target_68) {
	exists(EqualityOperation target_26 |
		target_26.getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_26.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_26.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb1_835
		and target_26.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_26.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_26.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_26.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_66
		and target_67.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_26.getAnOperand().(VariableAccess).getLocation())
		and target_26.getAnOperand().(VariableAccess).getLocation().isBefore(target_68.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_27(Variable va0_1_834, Variable vb1_835, ReturnStmt target_69, ExprStmt target_70, LogicalOrExpr target_71) {
	exists(EqualityOperation target_27 |
		target_27.getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_27.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_27.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb1_835
		and target_27.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_27.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_27.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_27.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_69
		and target_70.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_27.getAnOperand().(VariableAccess).getLocation())
		and target_27.getAnOperand().(VariableAccess).getLocation().isBefore(target_71.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_29(Variable va0_1_834, Variable vb1_835, ReturnStmt target_72, ExprStmt target_73, LogicalOrExpr target_74) {
	exists(EqualityOperation target_29 |
		target_29.getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_29.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_29.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb1_835
		and target_29.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_29.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_29.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_29.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_72
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_29.getAnOperand().(VariableAccess).getLocation())
		and target_29.getAnOperand().(VariableAccess).getLocation().isBefore(target_74.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_33(Variable va0_1_834, Variable vb1_835, ReturnStmt target_75, ExprStmt target_76, LogicalOrExpr target_77) {
	exists(EqualityOperation target_33 |
		target_33.getAnOperand().(VariableAccess).getTarget()=va0_1_834
		and target_33.getAnOperand().(UnaryMinusExpr).getValue()="4294967295"
		and target_33.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb1_835
		and target_33.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="3"
		and target_33.getParent().(LogicalOrExpr).getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_33.getParent().(LogicalOrExpr).getAnOperand() instanceof RelationalOperation
		and target_33.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_75
		and target_76.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation().isBefore(target_33.getAnOperand().(VariableAccess).getLocation())
		and target_33.getAnOperand().(VariableAccess).getLocation().isBefore(target_77.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getLocation()))
}

predicate func_34(Parameter vmmr_832, Variable va0_1_834, BreakStmt target_50, RelationalOperation target_34) {
		 (target_34 instanceof GEExpr or target_34 instanceof LEExpr)
		and target_34.getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_34.getLesserOperand().(PointerFieldAccess).getTarget().getName()="width"
		and target_34.getLesserOperand().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmr_832
		and target_34.getParent().(IfStmt).getThen()=target_50
}

predicate func_35(Variable va0_1_834, ReturnStmt target_54, RelationalOperation target_35) {
		 (target_35 instanceof GTExpr or target_35 instanceof LTExpr)
		and target_35.getLesserOperand().(VariableAccess).getTarget()=va0_1_834
		and target_35.getGreaterOperand().(Literal).getValue()="0"
		and target_35.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_54
}

predicate func_36(Variable vb1_835, BreakStmt target_78, SubExpr target_36) {
		target_36.getLeftOperand().(VariableAccess).getTarget()=vb1_835
		and target_36.getRightOperand().(Literal).getValue()="1"
		and target_36.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_36.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_78
}

predicate func_37(Variable vb1_835, BreakStmt target_79, SubExpr target_37) {
		target_37.getLeftOperand().(VariableAccess).getTarget()=vb1_835
		and target_37.getRightOperand().(Literal).getValue()="2"
		and target_37.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_37.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_79
}

predicate func_38(Variable vb1_835, BreakStmt target_80, SubExpr target_38) {
		target_38.getLeftOperand().(VariableAccess).getTarget()=vb1_835
		and target_38.getRightOperand().(Literal).getValue()="3"
		and target_38.getParent().(LTExpr).getGreaterOperand() instanceof Literal
		and target_38.getParent().(LTExpr).getParent().(IfStmt).getThen()=target_80
}

predicate func_40(Variable va0_1_834, ExprStmt target_49, VariableAccess target_40) {
		target_40.getTarget()=va0_1_834
		and target_40.getParent().(EQExpr).getAnOperand() instanceof UnaryMinusExpr
		and target_40.getParent().(EQExpr).getParent().(IfStmt).getThen()=target_49
}

predicate func_41(Variable va1_835, ReturnStmt target_51, RelationalOperation target_41) {
		 (target_41 instanceof GTExpr or target_41 instanceof LTExpr)
		and target_41.getLesserOperand().(VariableAccess).getTarget()=va1_835
		and target_41.getGreaterOperand() instanceof Literal
		and target_41.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_51
}

predicate func_42(Variable va0_1_834, ReturnStmt target_57, ExprStmt target_81, RelationalOperation target_42) {
		 (target_42 instanceof GTExpr or target_42 instanceof LTExpr)
		and target_42.getLesserOperand().(VariableAccess).getTarget()=va0_1_834
		and target_42.getGreaterOperand() instanceof Literal
		and target_42.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_57
		and target_42.getLesserOperand().(VariableAccess).getLocation().isBefore(target_81.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_43(Variable va0_1_834, ReturnStmt target_60, ExprStmt target_82, RelationalOperation target_43) {
		 (target_43 instanceof GTExpr or target_43 instanceof LTExpr)
		and target_43.getLesserOperand().(VariableAccess).getTarget()=va0_1_834
		and target_43.getGreaterOperand() instanceof Literal
		and target_43.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_60
		and target_43.getLesserOperand().(VariableAccess).getLocation().isBefore(target_82.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_44(Variable va0_1_834, ReturnStmt target_63, ExprStmt target_83, RelationalOperation target_44) {
		 (target_44 instanceof GTExpr or target_44 instanceof LTExpr)
		and target_44.getLesserOperand().(VariableAccess).getTarget()=va0_1_834
		and target_44.getGreaterOperand() instanceof Literal
		and target_44.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_63
		and target_44.getLesserOperand().(VariableAccess).getLocation().isBefore(target_83.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_45(Variable va0_1_834, ReturnStmt target_66, ExprStmt target_84, RelationalOperation target_45) {
		 (target_45 instanceof GTExpr or target_45 instanceof LTExpr)
		and target_45.getLesserOperand().(VariableAccess).getTarget()=va0_1_834
		and target_45.getGreaterOperand() instanceof Literal
		and target_45.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_66
		and target_45.getLesserOperand().(VariableAccess).getLocation().isBefore(target_84.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_46(Variable va0_1_834, ReturnStmt target_69, ExprStmt target_85, RelationalOperation target_46) {
		 (target_46 instanceof GTExpr or target_46 instanceof LTExpr)
		and target_46.getLesserOperand().(VariableAccess).getTarget()=va0_1_834
		and target_46.getGreaterOperand() instanceof Literal
		and target_46.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_69
		and target_46.getLesserOperand().(VariableAccess).getLocation().isBefore(target_85.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_47(Variable va0_1_834, ReturnStmt target_72, ExprStmt target_86, RelationalOperation target_47) {
		 (target_47 instanceof GTExpr or target_47 instanceof LTExpr)
		and target_47.getLesserOperand().(VariableAccess).getTarget()=va0_1_834
		and target_47.getGreaterOperand() instanceof Literal
		and target_47.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_72
		and target_47.getLesserOperand().(VariableAccess).getLocation().isBefore(target_86.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_48(Variable va0_1_834, ReturnStmt target_75, ExprStmt target_87, RelationalOperation target_48) {
		 (target_48 instanceof GTExpr or target_48 instanceof LTExpr)
		and target_48.getLesserOperand().(VariableAccess).getTarget()=va0_1_834
		and target_48.getGreaterOperand() instanceof Literal
		and target_48.getParent().(LogicalOrExpr).getParent().(IfStmt).getThen()=target_75
		and target_48.getLesserOperand().(VariableAccess).getLocation().isBefore(target_87.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation())
}

predicate func_49(Variable va0_1_834, ExprStmt target_49) {
		target_49.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=va0_1_834
		and target_49.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_50(BreakStmt target_50) {
		target_50.toString() = "break;"
}

predicate func_51(ReturnStmt target_51) {
		target_51.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_52(Parameter vmmr_832, Variable va1_835, ExprStmt target_52) {
		target_52.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=va1_835
		and target_52.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getTarget().getName()="width"
		and target_52.getExpr().(AssignExpr).getRValue().(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmr_832
}

predicate func_53(Variable va1_835, LogicalOrExpr target_53) {
		target_53.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va1_835
		and target_53.getAnOperand() instanceof RelationalOperation
}

predicate func_54(ReturnStmt target_54) {
		target_54.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_55(Variable va0_1_834, Variable va1_835, ExprStmt target_55) {
		target_55.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=va1_835
		and target_55.getExpr().(AssignExpr).getRValue().(AddExpr).getAnOperand().(VariableAccess).getTarget()=va0_1_834
}

predicate func_56(Variable va0_1_834, Variable va1_835, LogicalOrExpr target_56) {
		target_56.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=va1_835
		and target_56.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_56.getAnOperand() instanceof RelationalOperation
}

predicate func_57(ReturnStmt target_57) {
		target_57.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_58(Parameter vmmr_832, Variable va0_1_834, Variable vb1_835, ExprStmt target_58) {
		target_58.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vb1_835
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_find_changing_element_of_color")
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_58.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmr_832
}

predicate func_59(Variable va0_1_834, LogicalOrExpr target_59) {
		target_59.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_59.getAnOperand() instanceof RelationalOperation
}

predicate func_60(ReturnStmt target_60) {
		target_60.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_61(Parameter vmmr_832, Variable va0_1_834, Variable vb1_835, ExprStmt target_61) {
		target_61.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vb1_835
		and target_61.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_find_changing_element_of_color")
		and target_61.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_61.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_61.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmr_832
}

predicate func_62(Variable va0_1_834, Variable vb1_835, LogicalOrExpr target_62) {
		target_62.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vb1_835
		and target_62.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_62.getAnOperand() instanceof RelationalOperation
}

predicate func_63(ReturnStmt target_63) {
		target_63.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_64(Parameter vmmr_832, Variable va0_1_834, Variable vb1_835, ExprStmt target_64) {
		target_64.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vb1_835
		and target_64.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_find_changing_element_of_color")
		and target_64.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_64.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_64.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmr_832
}

predicate func_65(Variable va0_1_834, Variable vb1_835, LogicalOrExpr target_65) {
		target_65.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb1_835
		and target_65.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="1"
		and target_65.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_65.getAnOperand() instanceof RelationalOperation
}

predicate func_66(ReturnStmt target_66) {
		target_66.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_67(Parameter vmmr_832, Variable va0_1_834, Variable vb1_835, ExprStmt target_67) {
		target_67.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vb1_835
		and target_67.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_find_changing_element_of_color")
		and target_67.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_67.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_67.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmr_832
}

predicate func_68(Variable va0_1_834, Variable vb1_835, LogicalOrExpr target_68) {
		target_68.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb1_835
		and target_68.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="2"
		and target_68.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_68.getAnOperand() instanceof RelationalOperation
}

predicate func_69(ReturnStmt target_69) {
		target_69.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_70(Parameter vmmr_832, Variable va0_1_834, Variable vb1_835, ExprStmt target_70) {
		target_70.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vb1_835
		and target_70.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_find_changing_element_of_color")
		and target_70.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_70.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_70.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmr_832
}

predicate func_71(Variable va0_1_834, Variable vb1_835, LogicalOrExpr target_71) {
		target_71.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb1_835
		and target_71.getAnOperand().(RelationalOperation).getLesserOperand().(AddExpr).getAnOperand().(Literal).getValue()="3"
		and target_71.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_71.getAnOperand() instanceof RelationalOperation
}

predicate func_72(ReturnStmt target_72) {
		target_72.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_73(Parameter vmmr_832, Variable va0_1_834, Variable vb1_835, ExprStmt target_73) {
		target_73.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vb1_835
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_find_changing_element_of_color")
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_73.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmr_832
}

predicate func_74(Variable va0_1_834, Variable vb1_835, LogicalOrExpr target_74) {
		target_74.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb1_835
		and target_74.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="1"
		and target_74.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_74.getAnOperand() instanceof RelationalOperation
}

predicate func_75(ReturnStmt target_75) {
		target_75.getExpr().(UnaryMinusExpr).getValue()="-1"
}

predicate func_76(Parameter vmmr_832, Variable va0_1_834, Variable vb1_835, ExprStmt target_76) {
		target_76.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vb1_835
		and target_76.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("jbig2_find_changing_element_of_color")
		and target_76.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_76.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getTarget().getName()="width"
		and target_76.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(PointerFieldAccess).getQualifier().(VariableAccess).getTarget()=vmmr_832
}

predicate func_77(Variable va0_1_834, Variable vb1_835, LogicalOrExpr target_77) {
		target_77.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb1_835
		and target_77.getAnOperand().(RelationalOperation).getLesserOperand().(SubExpr).getRightOperand().(Literal).getValue()="3"
		and target_77.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=va0_1_834
		and target_77.getAnOperand() instanceof RelationalOperation
}

predicate func_78(BreakStmt target_78) {
		target_78.toString() = "break;"
}

predicate func_79(BreakStmt target_79) {
		target_79.toString() = "break;"
}

predicate func_80(BreakStmt target_80) {
		target_80.toString() = "break;"
}

predicate func_81(Variable va0_1_834, ExprStmt target_81) {
		target_81.getExpr().(FunctionCall).getTarget().hasName("jbig2_set_bits")
		and target_81.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
}

predicate func_82(Variable va0_1_834, Variable vb1_835, ExprStmt target_82) {
		target_82.getExpr().(FunctionCall).getTarget().hasName("jbig2_set_bits")
		and target_82.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_82.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vb1_835
}

predicate func_83(Variable va0_1_834, Variable vb1_835, ExprStmt target_83) {
		target_83.getExpr().(FunctionCall).getTarget().hasName("jbig2_set_bits")
		and target_83.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_83.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb1_835
		and target_83.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="1"
}

predicate func_84(Variable va0_1_834, Variable vb1_835, ExprStmt target_84) {
		target_84.getExpr().(FunctionCall).getTarget().hasName("jbig2_set_bits")
		and target_84.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_84.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb1_835
		and target_84.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="2"
}

predicate func_85(Variable va0_1_834, Variable vb1_835, ExprStmt target_85) {
		target_85.getExpr().(FunctionCall).getTarget().hasName("jbig2_set_bits")
		and target_85.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_85.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(VariableAccess).getTarget()=vb1_835
		and target_85.getExpr().(FunctionCall).getArgument(2).(AddExpr).getAnOperand().(Literal).getValue()="3"
}

predicate func_86(Variable va0_1_834, Variable vb1_835, ExprStmt target_86) {
		target_86.getExpr().(FunctionCall).getTarget().hasName("jbig2_set_bits")
		and target_86.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_86.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb1_835
		and target_86.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="1"
}

predicate func_87(Variable va0_1_834, Variable vb1_835, ExprStmt target_87) {
		target_87.getExpr().(FunctionCall).getTarget().hasName("jbig2_set_bits")
		and target_87.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=va0_1_834
		and target_87.getExpr().(FunctionCall).getArgument(2).(SubExpr).getLeftOperand().(VariableAccess).getTarget()=vb1_835
		and target_87.getExpr().(FunctionCall).getArgument(2).(SubExpr).getRightOperand().(Literal).getValue()="3"
}

from Function func, Parameter vmmr_832, Variable va0_1_834, Variable va1_835, Variable vb1_835, UnaryMinusExpr target_0, UnaryMinusExpr target_1, Literal target_6, Literal target_7, Literal target_8, Literal target_9, Literal target_10, Literal target_11, Literal target_12, Literal target_13, Literal target_14, Literal target_15, Literal target_16, RelationalOperation target_34, RelationalOperation target_35, SubExpr target_36, SubExpr target_37, SubExpr target_38, VariableAccess target_40, RelationalOperation target_41, RelationalOperation target_42, RelationalOperation target_43, RelationalOperation target_44, RelationalOperation target_45, RelationalOperation target_46, RelationalOperation target_47, RelationalOperation target_48, ExprStmt target_49, BreakStmt target_50, ReturnStmt target_51, ExprStmt target_52, LogicalOrExpr target_53, ReturnStmt target_54, ExprStmt target_55, LogicalOrExpr target_56, ReturnStmt target_57, ExprStmt target_58, LogicalOrExpr target_59, ReturnStmt target_60, ExprStmt target_61, LogicalOrExpr target_62, ReturnStmt target_63, ExprStmt target_64, LogicalOrExpr target_65, ReturnStmt target_66, ExprStmt target_67, LogicalOrExpr target_68, ReturnStmt target_69, ExprStmt target_70, LogicalOrExpr target_71, ReturnStmt target_72, ExprStmt target_73, LogicalOrExpr target_74, ReturnStmt target_75, ExprStmt target_76, LogicalOrExpr target_77, BreakStmt target_78, BreakStmt target_79, BreakStmt target_80, ExprStmt target_81, ExprStmt target_82, ExprStmt target_83, ExprStmt target_84, ExprStmt target_85, ExprStmt target_86, ExprStmt target_87
where
func_0(func, target_0)
and func_1(va0_1_834, target_49, target_1)
and func_6(func, target_6)
and func_7(func, target_7)
and func_8(func, target_8)
and func_9(func, target_9)
and func_10(func, target_10)
and func_11(func, target_11)
and func_12(func, target_12)
and func_13(func, target_13)
and func_14(func, target_14)
and func_15(func, target_15)
and func_16(func, target_16)
and not func_18(va0_1_834, target_50, target_34)
and not func_20(va0_1_834, target_49)
and not func_21(va1_835, target_51, target_52, target_53)
and not func_22(va0_1_834, va1_835, target_54, target_55, target_56)
and not func_23(va0_1_834, target_57, target_58, target_59)
and not func_24(va0_1_834, vb1_835, target_60, target_61, target_62)
and not func_25(va0_1_834, vb1_835, target_63, target_64, target_65)
and not func_26(va0_1_834, vb1_835, target_66, target_67, target_68)
and not func_27(va0_1_834, vb1_835, target_69, target_70, target_71)
and not func_29(va0_1_834, vb1_835, target_72, target_73, target_74)
and not func_33(va0_1_834, vb1_835, target_75, target_76, target_77)
and func_34(vmmr_832, va0_1_834, target_50, target_34)
and func_35(va0_1_834, target_54, target_35)
and func_36(vb1_835, target_78, target_36)
and func_37(vb1_835, target_79, target_37)
and func_38(vb1_835, target_80, target_38)
and func_40(va0_1_834, target_49, target_40)
and func_41(va1_835, target_51, target_41)
and func_42(va0_1_834, target_57, target_81, target_42)
and func_43(va0_1_834, target_60, target_82, target_43)
and func_44(va0_1_834, target_63, target_83, target_44)
and func_45(va0_1_834, target_66, target_84, target_45)
and func_46(va0_1_834, target_69, target_85, target_46)
and func_47(va0_1_834, target_72, target_86, target_47)
and func_48(va0_1_834, target_75, target_87, target_48)
and func_49(va0_1_834, target_49)
and func_50(target_50)
and func_51(target_51)
and func_52(vmmr_832, va1_835, target_52)
and func_53(va1_835, target_53)
and func_54(target_54)
and func_55(va0_1_834, va1_835, target_55)
and func_56(va0_1_834, va1_835, target_56)
and func_57(target_57)
and func_58(vmmr_832, va0_1_834, vb1_835, target_58)
and func_59(va0_1_834, target_59)
and func_60(target_60)
and func_61(vmmr_832, va0_1_834, vb1_835, target_61)
and func_62(va0_1_834, vb1_835, target_62)
and func_63(target_63)
and func_64(vmmr_832, va0_1_834, vb1_835, target_64)
and func_65(va0_1_834, vb1_835, target_65)
and func_66(target_66)
and func_67(vmmr_832, va0_1_834, vb1_835, target_67)
and func_68(va0_1_834, vb1_835, target_68)
and func_69(target_69)
and func_70(vmmr_832, va0_1_834, vb1_835, target_70)
and func_71(va0_1_834, vb1_835, target_71)
and func_72(target_72)
and func_73(vmmr_832, va0_1_834, vb1_835, target_73)
and func_74(va0_1_834, vb1_835, target_74)
and func_75(target_75)
and func_76(vmmr_832, va0_1_834, vb1_835, target_76)
and func_77(va0_1_834, vb1_835, target_77)
and func_78(target_78)
and func_79(target_79)
and func_80(target_80)
and func_81(va0_1_834, target_81)
and func_82(va0_1_834, vb1_835, target_82)
and func_83(va0_1_834, vb1_835, target_83)
and func_84(va0_1_834, vb1_835, target_84)
and func_85(va0_1_834, vb1_835, target_85)
and func_86(va0_1_834, vb1_835, target_86)
and func_87(va0_1_834, vb1_835, target_87)
and vmmr_832.getType().hasName("Jbig2MmrCtx *")
and va0_1_834.getType().hasName("int")
and va1_835.getType().hasName("int")
and vb1_835.getType().hasName("int")
and vmmr_832.getParentScope+() = func
and va0_1_834.getParentScope+() = func
and va1_835.getParentScope+() = func
and vb1_835.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
