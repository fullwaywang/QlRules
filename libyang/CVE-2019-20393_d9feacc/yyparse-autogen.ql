/**
 * @name libyang-d9feacc4a590d35dbc1af21caf9080008b4450ed-yyparse
 * @id cpp/libyang/d9feacc4a590d35dbc1af21caf9080008b4450ed/yyparse
 * @description libyang-d9feacc4a590d35dbc1af21caf9080008b4450ed-src/parser_yang_bis.c-yyparse CVE-2019-20393
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vs_2785, BlockStmt target_36, ExprStmt target_37, FunctionCall target_38) {
	exists(AddressOfExpr target_0 |
		target_0.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_0.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="belongs-to"
		and target_0.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_0.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_0.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_36
		and target_37.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getOperand().(VariableAccess).getLocation())
		and target_0.getOperand().(VariableAccess).getLocation().isBefore(target_38.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_1(Variable vs_2785, BlockStmt target_39, ExprStmt target_40, FunctionCall target_41) {
	exists(AddressOfExpr target_1 |
		target_1.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_1.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="prefix"
		and target_1.getParent().(FunctionCall).getArgument(3).(StringLiteral).getValue()="belongs-to"
		and target_1.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_1.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_39
		and target_40.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_1.getOperand().(VariableAccess).getLocation())
		and target_1.getOperand().(VariableAccess).getLocation().isBefore(target_41.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_2(Variable vs_2785, BlockStmt target_42, ExprStmt target_43, FunctionCall target_44) {
	exists(AddressOfExpr target_2 |
		target_2.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_2.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="argument"
		and target_2.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_2.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_2.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_42
		and target_43.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getOperand().(VariableAccess).getLocation())
		and target_2.getOperand().(VariableAccess).getLocation().isBefore(target_44.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_3(Variable vs_2785, BlockStmt target_45, ExprStmt target_46, FunctionCall target_47) {
	exists(AddressOfExpr target_3 |
		target_3.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_3.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="prefix"
		and target_3.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_3.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_3.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_45
		and target_46.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_3.getOperand().(VariableAccess).getLocation())
		and target_3.getOperand().(VariableAccess).getLocation().isBefore(target_47.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_4(Variable vs_2785, BlockStmt target_48, FunctionCall target_47, FunctionCall target_49) {
	exists(AddressOfExpr target_4 |
		target_4.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_4.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="description"
		and target_4.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_4.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_4.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_48
		and target_47.getArgument(4).(VariableAccess).getLocation().isBefore(target_4.getOperand().(VariableAccess).getLocation())
		and target_4.getOperand().(VariableAccess).getLocation().isBefore(target_49.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_5(Variable vs_2785, BlockStmt target_50, FunctionCall target_49, FunctionCall target_51) {
	exists(AddressOfExpr target_5 |
		target_5.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_5.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="reference"
		and target_5.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_5.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_5.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_50
		and target_49.getArgument(4).(VariableAccess).getLocation().isBefore(target_5.getOperand().(VariableAccess).getLocation())
		and target_5.getOperand().(VariableAccess).getLocation().isBefore(target_51.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_6(Variable vs_2785, BlockStmt target_52, FunctionCall target_51, FunctionCall target_53) {
	exists(AddressOfExpr target_6 |
		target_6.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_6.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="units"
		and target_6.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_6.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_6.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_52
		and target_51.getArgument(4).(VariableAccess).getLocation().isBefore(target_6.getOperand().(VariableAccess).getLocation())
		and target_6.getOperand().(VariableAccess).getLocation().isBefore(target_53.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_7(Variable vs_2785, BlockStmt target_54, FunctionCall target_53, FunctionCall target_55) {
	exists(AddressOfExpr target_7 |
		target_7.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_7.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="base"
		and target_7.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_7.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_7.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_54
		and target_53.getArgument(4).(VariableAccess).getLocation().isBefore(target_7.getOperand().(VariableAccess).getLocation())
		and target_7.getOperand().(VariableAccess).getLocation().isBefore(target_55.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_8(Variable vs_2785, BlockStmt target_56, FunctionCall target_55, FunctionCall target_57) {
	exists(AddressOfExpr target_8 |
		target_8.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_8.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="contact"
		and target_8.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_8.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_8.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_56
		and target_55.getArgument(4).(VariableAccess).getLocation().isBefore(target_8.getOperand().(VariableAccess).getLocation())
		and target_8.getOperand().(VariableAccess).getLocation().isBefore(target_57.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_9(Variable vs_2785, BlockStmt target_58, FunctionCall target_57, FunctionCall target_59) {
	exists(AddressOfExpr target_9 |
		target_9.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_9.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="default"
		and target_9.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_9.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_9.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_58
		and target_57.getArgument(4).(VariableAccess).getLocation().isBefore(target_9.getOperand().(VariableAccess).getLocation())
		and target_9.getOperand().(VariableAccess).getLocation().isBefore(target_59.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_10(Variable vs_2785, BlockStmt target_60, FunctionCall target_59, FunctionCall target_61) {
	exists(AddressOfExpr target_10 |
		target_10.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_10.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="error-message"
		and target_10.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_10.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_10.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_60
		and target_59.getArgument(4).(VariableAccess).getLocation().isBefore(target_10.getOperand().(VariableAccess).getLocation())
		and target_10.getOperand().(VariableAccess).getLocation().isBefore(target_61.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_11(Variable vs_2785, BlockStmt target_62, FunctionCall target_61, FunctionCall target_63) {
	exists(AddressOfExpr target_11 |
		target_11.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_11.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="error-app-tag"
		and target_11.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_11.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_11.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_62
		and target_61.getArgument(4).(VariableAccess).getLocation().isBefore(target_11.getOperand().(VariableAccess).getLocation())
		and target_11.getOperand().(VariableAccess).getLocation().isBefore(target_63.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_12(Variable vs_2785, BlockStmt target_64, FunctionCall target_63, FunctionCall target_65) {
	exists(AddressOfExpr target_12 |
		target_12.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_12.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="key"
		and target_12.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_12.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_12.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_64
		and target_63.getArgument(4).(VariableAccess).getLocation().isBefore(target_12.getOperand().(VariableAccess).getLocation())
		and target_12.getOperand().(VariableAccess).getLocation().isBefore(target_65.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_13(Variable vs_2785, BlockStmt target_66, FunctionCall target_65, FunctionCall target_67) {
	exists(AddressOfExpr target_13 |
		target_13.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_13.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="namespace"
		and target_13.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_13.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_13.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_66
		and target_65.getArgument(4).(VariableAccess).getLocation().isBefore(target_13.getOperand().(VariableAccess).getLocation())
		and target_13.getOperand().(VariableAccess).getLocation().isBefore(target_67.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_14(Variable vs_2785, BlockStmt target_68, FunctionCall target_67, FunctionCall target_69) {
	exists(AddressOfExpr target_14 |
		target_14.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_14.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="organization"
		and target_14.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_14.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_14.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_68
		and target_67.getArgument(4).(VariableAccess).getLocation().isBefore(target_14.getOperand().(VariableAccess).getLocation())
		and target_14.getOperand().(VariableAccess).getLocation().isBefore(target_69.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_15(Variable vs_2785, BlockStmt target_70, FunctionCall target_69, FunctionCall target_71) {
	exists(AddressOfExpr target_15 |
		target_15.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_15.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="path"
		and target_15.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_15.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_15.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_70
		and target_69.getArgument(4).(VariableAccess).getLocation().isBefore(target_15.getOperand().(VariableAccess).getLocation())
		and target_15.getOperand().(VariableAccess).getLocation().isBefore(target_71.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_16(Variable vs_2785, BlockStmt target_72, FunctionCall target_71, FunctionCall target_73) {
	exists(AddressOfExpr target_16 |
		target_16.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_16.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="presence"
		and target_16.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_16.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_16.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_72
		and target_71.getArgument(4).(VariableAccess).getLocation().isBefore(target_16.getOperand().(VariableAccess).getLocation())
		and target_16.getOperand().(VariableAccess).getLocation().isBefore(target_73.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_17(Variable vs_2785, BlockStmt target_74, FunctionCall target_73, FunctionCall target_75) {
	exists(AddressOfExpr target_17 |
		target_17.getOperand().(VariableAccess).getTarget()=vs_2785
		and target_17.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="revision-date"
		and target_17.getParent().(FunctionCall).getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_17.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_17.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_74
		and target_73.getArgument(4).(VariableAccess).getLocation().isBefore(target_17.getOperand().(VariableAccess).getLocation())
		and target_17.getOperand().(VariableAccess).getLocation().isBefore(target_75.getArgument(4).(VariableAccess).getLocation()))
}

predicate func_18(Variable vs_2785, BlockStmt target_36, ExprStmt target_76, VariableAccess target_18) {
		target_18.getTarget()=vs_2785
		and target_18.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="belongs-to"
		and target_18.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_18.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_36
		and target_18.getLocation().isBefore(target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_19(Variable vs_2785, BlockStmt target_39, FunctionCall target_77, VariableAccess target_19) {
		target_19.getTarget()=vs_2785
		and target_19.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="prefix"
		and target_19.getParent().(FunctionCall).getArgument(3).(StringLiteral).getValue()="belongs-to"
		and target_19.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_39
		and target_19.getLocation().isBefore(target_77.getArgument(2).(VariableAccess).getLocation())
}

predicate func_20(Variable vs_2785, BlockStmt target_42, ExprStmt target_78, VariableAccess target_20) {
		target_20.getTarget()=vs_2785
		and target_20.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="argument"
		and target_20.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_20.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_42
		and target_20.getLocation().isBefore(target_78.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getLocation())
}

predicate func_21(Variable vs_2785, BlockStmt target_45, VariableAccess target_21) {
		target_21.getTarget()=vs_2785
		and target_21.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="prefix"
		and target_21.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_21.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_45
}

predicate func_22(Variable vs_2785, BlockStmt target_48, VariableAccess target_22) {
		target_22.getTarget()=vs_2785
		and target_22.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="description"
		and target_22.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_22.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_48
}

predicate func_23(Variable vs_2785, BlockStmt target_50, VariableAccess target_23) {
		target_23.getTarget()=vs_2785
		and target_23.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="reference"
		and target_23.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_23.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_50
}

predicate func_24(Variable vs_2785, BlockStmt target_52, VariableAccess target_24) {
		target_24.getTarget()=vs_2785
		and target_24.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="units"
		and target_24.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_24.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_52
}

predicate func_25(Variable vs_2785, BlockStmt target_54, VariableAccess target_25) {
		target_25.getTarget()=vs_2785
		and target_25.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="base"
		and target_25.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_25.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_54
}

predicate func_26(Variable vs_2785, BlockStmt target_56, VariableAccess target_26) {
		target_26.getTarget()=vs_2785
		and target_26.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="contact"
		and target_26.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_26.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_56
}

predicate func_27(Variable vs_2785, BlockStmt target_58, VariableAccess target_27) {
		target_27.getTarget()=vs_2785
		and target_27.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="default"
		and target_27.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_27.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_58
}

predicate func_28(Variable vs_2785, BlockStmt target_60, VariableAccess target_28) {
		target_28.getTarget()=vs_2785
		and target_28.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="error-message"
		and target_28.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_28.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_60
}

predicate func_29(Variable vs_2785, BlockStmt target_62, VariableAccess target_29) {
		target_29.getTarget()=vs_2785
		and target_29.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="error-app-tag"
		and target_29.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_29.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_62
}

predicate func_30(Variable vs_2785, BlockStmt target_64, VariableAccess target_30) {
		target_30.getTarget()=vs_2785
		and target_30.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="key"
		and target_30.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_30.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_64
}

predicate func_31(Variable vs_2785, BlockStmt target_66, VariableAccess target_31) {
		target_31.getTarget()=vs_2785
		and target_31.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="namespace"
		and target_31.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_31.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_66
}

predicate func_32(Variable vs_2785, BlockStmt target_68, VariableAccess target_32) {
		target_32.getTarget()=vs_2785
		and target_32.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="organization"
		and target_32.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_32.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_68
}

predicate func_33(Variable vs_2785, BlockStmt target_70, VariableAccess target_33) {
		target_33.getTarget()=vs_2785
		and target_33.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="path"
		and target_33.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_33.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_70
}

predicate func_34(Variable vs_2785, BlockStmt target_72, VariableAccess target_34) {
		target_34.getTarget()=vs_2785
		and target_34.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="presence"
		and target_34.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_34.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_72
}

predicate func_35(Variable vs_2785, BlockStmt target_74, ExprStmt target_79, VariableAccess target_35) {
		target_35.getTarget()=vs_2785
		and target_35.getParent().(FunctionCall).getArgument(2).(StringLiteral).getValue()="revision-date"
		and target_35.getParent().(FunctionCall).getArgument(5).(Literal).getValue()="0"
		and target_35.getParent().(FunctionCall).getParent().(IfStmt).getThen()=target_74
		and target_35.getLocation().isBefore(target_79.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getLocation())
}

predicate func_36(BlockStmt target_36) {
		target_36.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_36.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_37(Variable vs_2785, ExprStmt target_37) {
		target_37.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_37.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_38(Variable vs_2785, FunctionCall target_38) {
		target_38.getTarget().hasName("yang_read_extcomplex_str")
		and target_38.getArgument(2).(StringLiteral).getValue()="belongs-to"
		and target_38.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_38.getArgument(5).(Literal).getValue()="0"
}

predicate func_39(BlockStmt target_39) {
		target_39.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_39.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_40(Variable vs_2785, ExprStmt target_40) {
		target_40.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_40.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_41(Variable vs_2785, FunctionCall target_41) {
		target_41.getTarget().hasName("yang_read_extcomplex_str")
		and target_41.getArgument(2).(StringLiteral).getValue()="prefix"
		and target_41.getArgument(3).(StringLiteral).getValue()="belongs-to"
		and target_41.getArgument(4).(VariableAccess).getTarget()=vs_2785
}

predicate func_42(BlockStmt target_42) {
		target_42.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_42.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_43(Variable vs_2785, ExprStmt target_43) {
		target_43.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_43.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_44(Variable vs_2785, FunctionCall target_44) {
		target_44.getTarget().hasName("yang_read_extcomplex_str")
		and target_44.getArgument(2).(StringLiteral).getValue()="argument"
		and target_44.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_44.getArgument(5).(Literal).getValue()="0"
}

predicate func_45(BlockStmt target_45) {
		target_45.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_45.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_46(Variable vs_2785, ExprStmt target_46) {
		target_46.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vs_2785
		and target_46.getExpr().(AssignExpr).getRValue().(Literal).getValue()="0"
}

predicate func_47(Variable vs_2785, FunctionCall target_47) {
		target_47.getTarget().hasName("yang_read_extcomplex_str")
		and target_47.getArgument(2).(StringLiteral).getValue()="prefix"
		and target_47.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_47.getArgument(5).(Literal).getValue()="0"
}

predicate func_48(BlockStmt target_48) {
		target_48.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_48.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_49(Variable vs_2785, FunctionCall target_49) {
		target_49.getTarget().hasName("yang_read_extcomplex_str")
		and target_49.getArgument(2).(StringLiteral).getValue()="description"
		and target_49.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_49.getArgument(5).(Literal).getValue()="0"
}

predicate func_50(BlockStmt target_50) {
		target_50.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_50.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_51(Variable vs_2785, FunctionCall target_51) {
		target_51.getTarget().hasName("yang_read_extcomplex_str")
		and target_51.getArgument(2).(StringLiteral).getValue()="reference"
		and target_51.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_51.getArgument(5).(Literal).getValue()="0"
}

predicate func_52(BlockStmt target_52) {
		target_52.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_52.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_53(Variable vs_2785, FunctionCall target_53) {
		target_53.getTarget().hasName("yang_read_extcomplex_str")
		and target_53.getArgument(2).(StringLiteral).getValue()="units"
		and target_53.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_53.getArgument(5).(Literal).getValue()="0"
}

predicate func_54(BlockStmt target_54) {
		target_54.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_54.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_55(Variable vs_2785, FunctionCall target_55) {
		target_55.getTarget().hasName("yang_read_extcomplex_str")
		and target_55.getArgument(2).(StringLiteral).getValue()="base"
		and target_55.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_55.getArgument(5).(Literal).getValue()="0"
}

predicate func_56(BlockStmt target_56) {
		target_56.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_56.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_57(Variable vs_2785, FunctionCall target_57) {
		target_57.getTarget().hasName("yang_read_extcomplex_str")
		and target_57.getArgument(2).(StringLiteral).getValue()="contact"
		and target_57.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_57.getArgument(5).(Literal).getValue()="0"
}

predicate func_58(BlockStmt target_58) {
		target_58.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_58.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_59(Variable vs_2785, FunctionCall target_59) {
		target_59.getTarget().hasName("yang_read_extcomplex_str")
		and target_59.getArgument(2).(StringLiteral).getValue()="default"
		and target_59.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_59.getArgument(5).(Literal).getValue()="0"
}

predicate func_60(BlockStmt target_60) {
		target_60.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_60.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_61(Variable vs_2785, FunctionCall target_61) {
		target_61.getTarget().hasName("yang_read_extcomplex_str")
		and target_61.getArgument(2).(StringLiteral).getValue()="error-message"
		and target_61.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_61.getArgument(5).(Literal).getValue()="0"
}

predicate func_62(BlockStmt target_62) {
		target_62.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_62.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_63(Variable vs_2785, FunctionCall target_63) {
		target_63.getTarget().hasName("yang_read_extcomplex_str")
		and target_63.getArgument(2).(StringLiteral).getValue()="error-app-tag"
		and target_63.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_63.getArgument(5).(Literal).getValue()="0"
}

predicate func_64(BlockStmt target_64) {
		target_64.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_64.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_65(Variable vs_2785, FunctionCall target_65) {
		target_65.getTarget().hasName("yang_read_extcomplex_str")
		and target_65.getArgument(2).(StringLiteral).getValue()="key"
		and target_65.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_65.getArgument(5).(Literal).getValue()="0"
}

predicate func_66(BlockStmt target_66) {
		target_66.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_66.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_67(Variable vs_2785, FunctionCall target_67) {
		target_67.getTarget().hasName("yang_read_extcomplex_str")
		and target_67.getArgument(2).(StringLiteral).getValue()="namespace"
		and target_67.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_67.getArgument(5).(Literal).getValue()="0"
}

predicate func_68(BlockStmt target_68) {
		target_68.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_68.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_69(Variable vs_2785, FunctionCall target_69) {
		target_69.getTarget().hasName("yang_read_extcomplex_str")
		and target_69.getArgument(2).(StringLiteral).getValue()="organization"
		and target_69.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_69.getArgument(5).(Literal).getValue()="0"
}

predicate func_70(BlockStmt target_70) {
		target_70.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_70.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_71(Variable vs_2785, FunctionCall target_71) {
		target_71.getTarget().hasName("yang_read_extcomplex_str")
		and target_71.getArgument(2).(StringLiteral).getValue()="path"
		and target_71.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_71.getArgument(5).(Literal).getValue()="0"
}

predicate func_72(BlockStmt target_72) {
		target_72.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_72.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_73(Variable vs_2785, FunctionCall target_73) {
		target_73.getTarget().hasName("yang_read_extcomplex_str")
		and target_73.getArgument(2).(StringLiteral).getValue()="presence"
		and target_73.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_73.getArgument(5).(Literal).getValue()="0"
}

predicate func_74(BlockStmt target_74) {
		target_74.getStmt(0).(GotoStmt).toString() = "goto ..."
		and target_74.getStmt(0).(GotoStmt).getName() ="yyabortlab"
}

predicate func_75(Variable vs_2785, FunctionCall target_75) {
		target_75.getTarget().hasName("yang_read_extcomplex_str")
		and target_75.getArgument(2).(StringLiteral).getValue()="revision-date"
		and target_75.getArgument(4).(VariableAccess).getTarget()=vs_2785
		and target_75.getArgument(5).(Literal).getValue()="0"
}

predicate func_76(Variable vs_2785, ExprStmt target_76) {
		target_76.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_76.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_2785
}

predicate func_77(Variable vs_2785, FunctionCall target_77) {
		target_77.getTarget().hasName("yang_read_prefix")
		and target_77.getArgument(1).(Literal).getValue()="0"
		and target_77.getArgument(2).(VariableAccess).getTarget()=vs_2785
}

predicate func_78(Variable vs_2785, ExprStmt target_78) {
		target_78.getExpr().(FunctionCall).getTarget().hasName("free")
		and target_78.getExpr().(FunctionCall).getArgument(0).(VariableAccess).getTarget()=vs_2785
}

predicate func_79(Variable vs_2785, ExprStmt target_79) {
		target_79.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("yang_fill_unique")
		and target_79.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(VariableAccess).getTarget()=vs_2785
		and target_79.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(4).(PointerFieldAccess).getTarget().getName()="unres"
}

from Function func, Variable vs_2785, VariableAccess target_18, VariableAccess target_19, VariableAccess target_20, VariableAccess target_21, VariableAccess target_22, VariableAccess target_23, VariableAccess target_24, VariableAccess target_25, VariableAccess target_26, VariableAccess target_27, VariableAccess target_28, VariableAccess target_29, VariableAccess target_30, VariableAccess target_31, VariableAccess target_32, VariableAccess target_33, VariableAccess target_34, VariableAccess target_35, BlockStmt target_36, ExprStmt target_37, FunctionCall target_38, BlockStmt target_39, ExprStmt target_40, FunctionCall target_41, BlockStmt target_42, ExprStmt target_43, FunctionCall target_44, BlockStmt target_45, ExprStmt target_46, FunctionCall target_47, BlockStmt target_48, FunctionCall target_49, BlockStmt target_50, FunctionCall target_51, BlockStmt target_52, FunctionCall target_53, BlockStmt target_54, FunctionCall target_55, BlockStmt target_56, FunctionCall target_57, BlockStmt target_58, FunctionCall target_59, BlockStmt target_60, FunctionCall target_61, BlockStmt target_62, FunctionCall target_63, BlockStmt target_64, FunctionCall target_65, BlockStmt target_66, FunctionCall target_67, BlockStmt target_68, FunctionCall target_69, BlockStmt target_70, FunctionCall target_71, BlockStmt target_72, FunctionCall target_73, BlockStmt target_74, FunctionCall target_75, ExprStmt target_76, FunctionCall target_77, ExprStmt target_78, ExprStmt target_79
where
not func_0(vs_2785, target_36, target_37, target_38)
and not func_1(vs_2785, target_39, target_40, target_41)
and not func_2(vs_2785, target_42, target_43, target_44)
and not func_3(vs_2785, target_45, target_46, target_47)
and not func_4(vs_2785, target_48, target_47, target_49)
and not func_5(vs_2785, target_50, target_49, target_51)
and not func_6(vs_2785, target_52, target_51, target_53)
and not func_7(vs_2785, target_54, target_53, target_55)
and not func_8(vs_2785, target_56, target_55, target_57)
and not func_9(vs_2785, target_58, target_57, target_59)
and not func_10(vs_2785, target_60, target_59, target_61)
and not func_11(vs_2785, target_62, target_61, target_63)
and not func_12(vs_2785, target_64, target_63, target_65)
and not func_13(vs_2785, target_66, target_65, target_67)
and not func_14(vs_2785, target_68, target_67, target_69)
and not func_15(vs_2785, target_70, target_69, target_71)
and not func_16(vs_2785, target_72, target_71, target_73)
and not func_17(vs_2785, target_74, target_73, target_75)
and func_18(vs_2785, target_36, target_76, target_18)
and func_19(vs_2785, target_39, target_77, target_19)
and func_20(vs_2785, target_42, target_78, target_20)
and func_21(vs_2785, target_45, target_21)
and func_22(vs_2785, target_48, target_22)
and func_23(vs_2785, target_50, target_23)
and func_24(vs_2785, target_52, target_24)
and func_25(vs_2785, target_54, target_25)
and func_26(vs_2785, target_56, target_26)
and func_27(vs_2785, target_58, target_27)
and func_28(vs_2785, target_60, target_28)
and func_29(vs_2785, target_62, target_29)
and func_30(vs_2785, target_64, target_30)
and func_31(vs_2785, target_66, target_31)
and func_32(vs_2785, target_68, target_32)
and func_33(vs_2785, target_70, target_33)
and func_34(vs_2785, target_72, target_34)
and func_35(vs_2785, target_74, target_79, target_35)
and func_36(target_36)
and func_37(vs_2785, target_37)
and func_38(vs_2785, target_38)
and func_39(target_39)
and func_40(vs_2785, target_40)
and func_41(vs_2785, target_41)
and func_42(target_42)
and func_43(vs_2785, target_43)
and func_44(vs_2785, target_44)
and func_45(target_45)
and func_46(vs_2785, target_46)
and func_47(vs_2785, target_47)
and func_48(target_48)
and func_49(vs_2785, target_49)
and func_50(target_50)
and func_51(vs_2785, target_51)
and func_52(target_52)
and func_53(vs_2785, target_53)
and func_54(target_54)
and func_55(vs_2785, target_55)
and func_56(target_56)
and func_57(vs_2785, target_57)
and func_58(target_58)
and func_59(vs_2785, target_59)
and func_60(target_60)
and func_61(vs_2785, target_61)
and func_62(target_62)
and func_63(vs_2785, target_63)
and func_64(target_64)
and func_65(vs_2785, target_65)
and func_66(target_66)
and func_67(vs_2785, target_67)
and func_68(target_68)
and func_69(vs_2785, target_69)
and func_70(target_70)
and func_71(vs_2785, target_71)
and func_72(target_72)
and func_73(vs_2785, target_73)
and func_74(target_74)
and func_75(vs_2785, target_75)
and func_76(vs_2785, target_76)
and func_77(vs_2785, target_77)
and func_78(vs_2785, target_78)
and func_79(vs_2785, target_79)
and vs_2785.getType().hasName("char *")
and vs_2785.getParentScope+() = func
select func, func.getFile().toString() + ":" + func.getLocation().getStartLine().toString()
