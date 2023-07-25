/**
 * @name openssl-6f35f6deb5ca7daebe289f86477e061ce3ee5f46-ssl3_get_client_hello
 * @id cpp/openssl/6f35f6deb5ca7daebe289f86477e061ce3ee5f46/ssl3-get-client-hello
 * @description openssl-6f35f6deb5ca7daebe289f86477e061ce3ee5f46-ssl/s3_srvr.c-ssl3_get_client_hello CVE-2016-2177
 * @kind problem
 * @problem.severity error
 * @tags security
 */

import cpp

predicate func_0(Variable vsession_length_1039, BlockStmt target_37, ExprStmt target_38) {
	exists(AddExpr target_0 |
		target_0.getAnOperand().(AddExpr).getAnOperand().(Literal).getValue()="32"
		and target_0.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vsession_length_1039
		and target_0.getAnOperand() instanceof Literal
		and target_0.getParent().(GEExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_0.getParent().(GEExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_0.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_37
		and target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_0.getAnOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_1(Variable vp_973, BlockStmt target_37, ExprStmt target_40, ExprStmt target_41) {
	exists(PointerArithmeticOperation target_1 |
		target_1.getLeftOperand() instanceof PointerArithmeticOperation
		and target_1.getRightOperand().(VariableAccess).getTarget()=vp_973
		and target_1.getParent().(GEExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_1.getParent().(GEExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_1.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_37
		and target_40.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_1.getRightOperand().(VariableAccess).getLocation())
		and target_1.getRightOperand().(VariableAccess).getLocation().isBefore(target_41.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_2(Variable vj_969, Variable vp_973, BlockStmt target_42, ExprStmt target_40, LogicalOrExpr target_43, ExprStmt target_44, ExprStmt target_45) {
	exists(RelationalOperation target_2 |
		 (target_2 instanceof GTExpr or target_2 instanceof LTExpr)
		and target_2.getLesserOperand().(PointerArithmeticOperation).getLeftOperand() instanceof PointerArithmeticOperation
		and target_2.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_973
		and target_2.getGreaterOperand().(VariableAccess).getTarget()=vj_969
		and target_2.getParent().(IfStmt).getThen()=target_42
		and target_40.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getGreaterOperand().(VariableAccess).getLocation())
		and target_2.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_43.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getLocation())
		and target_44.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_2.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_2.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_45.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation()))
}

predicate func_3(Variable vp_973, BlockStmt target_46, ExprStmt target_45, ExprStmt target_47) {
	exists(RelationalOperation target_3 |
		 (target_3 instanceof GTExpr or target_3 instanceof LTExpr)
		and target_3.getLesserOperand().(PointerArithmeticOperation).getLeftOperand() instanceof PointerArithmeticOperation
		and target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_973
		and target_3.getGreaterOperand() instanceof Literal
		and target_3.getParent().(IfStmt).getThen()=target_46
		and target_45.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getLocation().isBefore(target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_3.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_47.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_4(Variable vcookie_len_970, Variable vp_973, BlockStmt target_48, ExprStmt target_45, RelationalOperation target_49, ExprStmt target_50, ExprStmt target_51) {
	exists(RelationalOperation target_4 |
		 (target_4 instanceof GTExpr or target_4 instanceof LTExpr)
		and target_4.getLesserOperand().(PointerArithmeticOperation).getLeftOperand() instanceof PointerArithmeticOperation
		and target_4.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_973
		and target_4.getGreaterOperand().(VariableAccess).getTarget()=vcookie_len_970
		and target_4.getParent().(IfStmt).getThen()=target_48
		and target_45.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getGreaterOperand().(VariableAccess).getLocation())
		and target_4.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_49.getGreaterOperand().(VariableAccess).getLocation())
		and target_50.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getLocation().isBefore(target_4.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_4.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_51.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation()))
}

predicate func_5(Variable vp_973, BlockStmt target_52, ExprStmt target_51, EqualityOperation target_53) {
	exists(RelationalOperation target_5 |
		 (target_5 instanceof GTExpr or target_5 instanceof LTExpr)
		and target_5.getLesserOperand().(PointerArithmeticOperation).getLeftOperand() instanceof PointerArithmeticOperation
		and target_5.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_973
		and target_5.getGreaterOperand() instanceof Literal
		and target_5.getParent().(IfStmt).getThen()=target_52
		and target_51.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getLocation().isBefore(target_5.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation())
		and target_5.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_53.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getLocation()))
}

predicate func_6(Variable vi_969, Variable vp_973, BlockStmt target_54, EqualityOperation target_55, EqualityOperation target_53, ExprStmt target_56) {
	exists(RelationalOperation target_6 |
		 (target_6 instanceof GTExpr or target_6 instanceof LTExpr)
		and target_6.getLesserOperand().(PointerArithmeticOperation).getLeftOperand() instanceof PointerArithmeticOperation
		and target_6.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_973
		and target_6.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getTarget()=vi_969
		and target_6.getGreaterOperand().(AddExpr).getAnOperand() instanceof Literal
		and target_6.getParent().(IfStmt).getThen()=target_54
		and target_55.getAnOperand().(VariableAccess).getLocation().isBefore(target_6.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation())
		and target_6.getGreaterOperand().(AddExpr).getAnOperand().(VariableAccess).getLocation().isBefore(target_53.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getLocation())
		and target_6.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_56.getExpr().(AssignExpr).getRValue().(VariableAccess).getLocation()))
}

predicate func_7(Variable vi_969, Variable vp_973, BlockStmt target_57, ExprStmt target_58, RelationalOperation target_59, RelationalOperation target_36) {
	exists(RelationalOperation target_7 |
		 (target_7 instanceof GTExpr or target_7 instanceof LTExpr)
		and target_7.getLesserOperand().(PointerArithmeticOperation).getLeftOperand() instanceof PointerArithmeticOperation
		and target_7.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getTarget()=vp_973
		and target_7.getGreaterOperand().(VariableAccess).getTarget()=vi_969
		and target_7.getParent().(IfStmt).getThen()=target_57
		and target_58.getExpr().(AssignExpr).getLValue().(VariableAccess).getLocation().isBefore(target_7.getGreaterOperand().(VariableAccess).getLocation())
		and target_7.getGreaterOperand().(VariableAccess).getLocation().isBefore(target_59.getGreaterOperand().(VariableAccess).getLocation())
		and target_7.getLesserOperand().(PointerArithmeticOperation).getRightOperand().(VariableAccess).getLocation().isBefore(target_36.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getLocation()))
}

predicate func_8(Variable vp_973, Variable vsession_length_1039, PointerArithmeticOperation target_8) {
		target_8.getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_973
		and target_8.getAnOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="32"
		and target_8.getAnOperand().(VariableAccess).getTarget()=vsession_length_1039
}

predicate func_9(Variable vn_971, Variable vd_973, BlockStmt target_37, PointerArithmeticOperation target_9) {
		target_9.getAnOperand().(VariableAccess).getTarget()=vd_973
		and target_9.getAnOperand().(VariableAccess).getTarget()=vn_971
		and target_9.getParent().(GEExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_9.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_37
}

predicate func_10(Variable vn_971, Variable vd_973, BlockStmt target_42, PointerArithmeticOperation target_10) {
		target_10.getAnOperand().(VariableAccess).getTarget()=vd_973
		and target_10.getAnOperand().(VariableAccess).getTarget()=vn_971
		and target_10.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_10.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_42
}

predicate func_11(Variable vn_971, Variable vd_973, BlockStmt target_46, PointerArithmeticOperation target_11) {
		target_11.getAnOperand().(VariableAccess).getTarget()=vd_973
		and target_11.getAnOperand().(VariableAccess).getTarget()=vn_971
		and target_11.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_11.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_46
}

predicate func_12(Variable vn_971, Variable vd_973, BlockStmt target_48, PointerArithmeticOperation target_12) {
		target_12.getAnOperand().(VariableAccess).getTarget()=vd_973
		and target_12.getAnOperand().(VariableAccess).getTarget()=vn_971
		and target_12.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_12.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_48
}

predicate func_13(Variable vn_971, Variable vd_973, BlockStmt target_52, PointerArithmeticOperation target_13) {
		target_13.getAnOperand().(VariableAccess).getTarget()=vd_973
		and target_13.getAnOperand().(VariableAccess).getTarget()=vn_971
		and target_13.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_13.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_52
}

predicate func_14(Variable vn_971, Variable vd_973, BlockStmt target_54, PointerArithmeticOperation target_14) {
		target_14.getAnOperand().(VariableAccess).getTarget()=vd_973
		and target_14.getAnOperand().(VariableAccess).getTarget()=vn_971
		and target_14.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_14.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_54
}

predicate func_15(Variable vn_971, Variable vd_973, BlockStmt target_57, PointerArithmeticOperation target_15) {
		target_15.getAnOperand().(VariableAccess).getTarget()=vd_973
		and target_15.getAnOperand().(VariableAccess).getTarget()=vn_971
		and target_15.getParent().(GTExpr).getGreaterOperand() instanceof PointerArithmeticOperation
		and target_15.getParent().(GTExpr).getParent().(IfStmt).getThen()=target_57
}

predicate func_18(Variable vp_973, VariableAccess target_18) {
		target_18.getTarget()=vp_973
}

predicate func_19(Variable vj_969, VariableAccess target_19) {
		target_19.getTarget()=vj_969
}

predicate func_20(Variable vp_973, VariableAccess target_20) {
		target_20.getTarget()=vp_973
}

predicate func_21(Variable vp_973, VariableAccess target_21) {
		target_21.getTarget()=vp_973
}

predicate func_22(Variable vcookie_len_970, VariableAccess target_22) {
		target_22.getTarget()=vcookie_len_970
}

predicate func_23(Variable vp_973, VariableAccess target_23) {
		target_23.getTarget()=vp_973
}

predicate func_25(Variable vp_973, VariableAccess target_25) {
		target_25.getTarget()=vp_973
}

predicate func_26(Variable vi_969, VariableAccess target_26) {
		target_26.getTarget()=vi_969
}

predicate func_28(Variable vp_973, VariableAccess target_28) {
		target_28.getTarget()=vp_973
}

predicate func_29(Variable vi_969, VariableAccess target_29) {
		target_29.getTarget()=vi_969
}

predicate func_30(BlockStmt target_37, Function func, PointerArithmeticOperation target_30) {
		target_30.getAnOperand() instanceof PointerArithmeticOperation
		and target_30.getAnOperand() instanceof Literal
		and target_30.getParent().(GEExpr).getLesserOperand() instanceof PointerArithmeticOperation
		and target_30.getParent().(GEExpr).getParent().(IfStmt).getThen()=target_37
		and target_30.getEnclosingFunction() = func
}

predicate func_31(Variable vj_969, Variable vp_973, BlockStmt target_42, RelationalOperation target_31) {
		 (target_31 instanceof GTExpr or target_31 instanceof LTExpr)
		and target_31.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_973
		and target_31.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vj_969
		and target_31.getLesserOperand() instanceof PointerArithmeticOperation
		and target_31.getParent().(IfStmt).getThen()=target_42
}

predicate func_32(Variable vp_973, BlockStmt target_46, RelationalOperation target_32) {
		 (target_32 instanceof GTExpr or target_32 instanceof LTExpr)
		and target_32.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_973
		and target_32.getGreaterOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_32.getLesserOperand() instanceof PointerArithmeticOperation
		and target_32.getParent().(IfStmt).getThen()=target_46
}

predicate func_33(Variable vcookie_len_970, Variable vp_973, BlockStmt target_48, RelationalOperation target_33) {
		 (target_33 instanceof GTExpr or target_33 instanceof LTExpr)
		and target_33.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_973
		and target_33.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vcookie_len_970
		and target_33.getLesserOperand() instanceof PointerArithmeticOperation
		and target_33.getParent().(IfStmt).getThen()=target_48
}

predicate func_34(Variable vp_973, BlockStmt target_52, RelationalOperation target_34) {
		 (target_34 instanceof GTExpr or target_34 instanceof LTExpr)
		and target_34.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_973
		and target_34.getGreaterOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_34.getLesserOperand() instanceof PointerArithmeticOperation
		and target_34.getParent().(IfStmt).getThen()=target_52
}

predicate func_35(Variable vi_969, Variable vp_973, BlockStmt target_54, RelationalOperation target_35) {
		 (target_35 instanceof GTExpr or target_35 instanceof LTExpr)
		and target_35.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_973
		and target_35.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_969
		and target_35.getGreaterOperand().(PointerArithmeticOperation).getAnOperand() instanceof Literal
		and target_35.getLesserOperand() instanceof PointerArithmeticOperation
		and target_35.getParent().(IfStmt).getThen()=target_54
}

predicate func_36(Variable vi_969, Variable vp_973, BlockStmt target_57, RelationalOperation target_36) {
		 (target_36 instanceof GTExpr or target_36 instanceof LTExpr)
		and target_36.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_973
		and target_36.getGreaterOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vi_969
		and target_36.getLesserOperand() instanceof PointerArithmeticOperation
		and target_36.getParent().(IfStmt).getThen()=target_57
}

predicate func_37(BlockStmt target_37) {
		target_37.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_37.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_37.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_37.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_37.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_37.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_37.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_38(Variable vp_973, Variable vsession_length_1039, ExprStmt target_38) {
		target_38.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vsession_length_1039
		and target_38.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vp_973
		and target_38.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PointerArithmeticOperation).getAnOperand().(Literal).getValue()="32"
}

predicate func_40(Variable vj_969, Variable vp_973, ExprStmt target_40) {
		target_40.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vj_969
		and target_40.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_973
}

predicate func_41(Variable vi_969, Variable vj_969, Variable vn_971, Variable vp_973, Variable vd_973, ExprStmt target_41) {
		target_41.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_969
		and target_41.getExpr().(AssignExpr).getRValue().(FunctionCall).getTarget().hasName("ssl_get_prev_session")
		and target_41.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_973
		and target_41.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vj_969
		and target_41.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vd_973
		and target_41.getExpr().(AssignExpr).getRValue().(FunctionCall).getArgument(3).(PointerArithmeticOperation).getAnOperand().(VariableAccess).getTarget()=vn_971
}

predicate func_42(BlockStmt target_42) {
		target_42.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_42.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_42.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_42.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_42.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_42.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_42.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_43(Variable vj_969, LogicalOrExpr target_43) {
		target_43.getAnOperand().(RelationalOperation).getLesserOperand().(VariableAccess).getTarget()=vj_969
		and target_43.getAnOperand().(RelationalOperation).getGreaterOperand().(Literal).getValue()="0"
		and target_43.getAnOperand().(RelationalOperation).getGreaterOperand().(VariableAccess).getTarget()=vj_969
		and target_43.getAnOperand().(RelationalOperation).getLesserOperand().(Literal).getValue()="32"
}

predicate func_44(Variable vj_969, Variable vp_973, ExprStmt target_44) {
		target_44.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_973
		and target_44.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vj_969
}

predicate func_45(Variable vcookie_len_970, Variable vp_973, ExprStmt target_45) {
		target_45.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vcookie_len_970
		and target_45.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_973
}

predicate func_46(BlockStmt target_46) {
		target_46.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_46.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_46.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_46.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_46.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_46.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_46.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_47(Variable vcookie_len_970, Variable vp_973, ExprStmt target_47) {
		target_47.getExpr().(FunctionCall).getTarget().hasName("memcpy")
		and target_47.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getTarget().getName()="rcvd_cookie"
		and target_47.getExpr().(FunctionCall).getArgument(0).(PointerFieldAccess).getQualifier().(PointerFieldAccess).getTarget().getName()="d1"
		and target_47.getExpr().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_973
		and target_47.getExpr().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vcookie_len_970
}

predicate func_48(BlockStmt target_48) {
		target_48.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_48.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_48.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_48.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_48.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_48.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_48.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_49(Variable vcookie_len_970, RelationalOperation target_49) {
		 (target_49 instanceof GTExpr or target_49 instanceof LTExpr)
		and target_49.getGreaterOperand().(VariableAccess).getTarget()=vcookie_len_970
		and target_49.getLesserOperand().(SizeofExprOperator).getValue()="256"
}

predicate func_50(Variable vcookie_len_970, Variable vp_973, ExprStmt target_50) {
		target_50.getExpr().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_973
		and target_50.getExpr().(AssignPointerAddExpr).getRValue().(VariableAccess).getTarget()=vcookie_len_970
}

predicate func_51(Variable vi_969, Variable vp_973, ExprStmt target_51) {
		target_51.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_969
		and target_51.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_973
		and target_51.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getLeftOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="0"
		and target_51.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getLeftOperand().(BinaryBitwiseOperation).getRightOperand().(Literal).getValue()="8"
		and target_51.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayBase().(VariableAccess).getTarget()=vp_973
		and target_51.getExpr().(CommaExpr).getLeftOperand().(AssignExpr).getRValue().(BitwiseOrExpr).getRightOperand().(ArrayExpr).getArrayOffset().(Literal).getValue()="1"
		and target_51.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getLValue().(VariableAccess).getTarget()=vp_973
		and target_51.getExpr().(CommaExpr).getRightOperand().(AssignPointerAddExpr).getRValue().(Literal).getValue()="2"
}

predicate func_52(BlockStmt target_52) {
		target_52.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_52.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_52.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_52.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_52.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_52.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_52.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_53(Variable vi_969, Variable vp_973, EqualityOperation target_53) {
		target_53.getAnOperand().(FunctionCall).getTarget().hasName("ssl_bytes_to_cipher_list")
		and target_53.getAnOperand().(FunctionCall).getArgument(1).(VariableAccess).getTarget()=vp_973
		and target_53.getAnOperand().(FunctionCall).getArgument(2).(VariableAccess).getTarget()=vi_969
		and target_53.getAnOperand().(Literal).getValue()="0"
}

predicate func_54(BlockStmt target_54) {
		target_54.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_54.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_54.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_54.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_54.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_54.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_54.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_55(Variable vi_969, EqualityOperation target_55) {
		target_55.getAnOperand().(VariableAccess).getTarget()=vi_969
		and target_55.getAnOperand().(Literal).getValue()="0"
}

predicate func_56(Variable vp_973, ExprStmt target_56) {
		target_56.getExpr().(AssignExpr).getRValue().(VariableAccess).getTarget()=vp_973
}

predicate func_57(BlockStmt target_57) {
		target_57.getStmt(0).(ExprStmt).getExpr().(AssignExpr).getRValue().(Literal).getValue()="50"
		and target_57.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getTarget().hasName("ERR_put_error")
		and target_57.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(0) instanceof Literal
		and target_57.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(1) instanceof Literal
		and target_57.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(2) instanceof Literal
		and target_57.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(3) instanceof StringLiteral
		and target_57.getStmt(1).(ExprStmt).getExpr().(FunctionCall).getArgument(4) instanceof Literal
}

predicate func_58(Variable vi_969, Variable vp_973, ExprStmt target_58) {
		target_58.getExpr().(AssignExpr).getLValue().(VariableAccess).getTarget()=vi_969
		and target_58.getExpr().(AssignExpr).getRValue().(PointerDereferenceExpr).getOperand().(PostfixIncrExpr).getOperand().(VariableAccess).getTarget()=vp_973
}

predicate func_59(Variable vi_969, Variable vj_969, RelationalOperation target_59) {
		 (target_59 instanceof GTExpr or target_59 instanceof LTExpr)
		and target_59.getLesserOperand().(VariableAccess).getTarget()=vj_969
		and target_59.getGreaterOperand().(VariableAccess).getTarget()=vi_969
}

from Function func, Variable vi_969, Variable vj_969, Variable vcookie_len_970, Variable vn_971, Variable vp_973, Variable vd_973, Variable vsession_length_1039, PointerArithmeticOperation target_8, PointerArithmeticOperation target_9, PointerArithmeticOperation target_10, PointerArithmeticOperation target_11, PointerArithmeticOperation target_12, PointerArithmeticOperation target_13, PointerArithmeticOperation target_14, PointerArithmeticOperation target_15, VariableAccess target_18, VariableAccess target_19, VariableAccess target_20, VariableAccess target_21, VariableAccess target_22, VariableAccess target_23, VariableAccess target_25, VariableAccess target_26, VariableAccess target_28, VariableAccess target_29, PointerArithmeticOperation target_30, RelationalOperation target_31, RelationalOperation target_32, RelationalOperation target_33, RelationalOperation target_34, RelationalOperation target_35, RelationalOperation target_36, BlockStmt target_37, ExprStmt target_38, ExprStmt target_40, ExprStmt target_41, BlockStmt target_42, LogicalOrExpr target_43, ExprStmt target_44, ExprStmt target_45, BlockStmt target_46, ExprStmt target_47, BlockStmt target_48, RelationalOperation target_49, ExprStmt target_50, ExprStmt target_51, BlockStmt target_52, EqualityOperation target_53, BlockStmt target_54, EqualityOperation target_55, ExprStmt target_56, BlockStmt target_57, ExprStmt target_58, RelationalOperation target_59
where
not func_0(vsession_length_1039, target_37, target_38)
and not func_1(vp_973, target_37, target_40, target_41)
and not func_2(vj_969, vp_973, target_42, target_40, target_43, target_44, target_45)
and not func_3(vp_973, target_46, target_45, target_47)
and not func_4(vcookie_len_970, vp_973, target_48, target_45, target_49, target_50, target_51)
and not func_5(vp_973, target_52, target_51, target_53)
and not func_6(vi_969, vp_973, target_54, target_55, target_53, target_56)
and not func_7(vi_969, vp_973, target_57, target_58, target_59, target_36)
and func_8(vp_973, vsession_length_1039, target_8)
and func_9(vn_971, vd_973, target_37, target_9)
and func_10(vn_971, vd_973, target_42, target_10)
and func_11(vn_971, vd_973, target_46, target_11)
and func_12(vn_971, vd_973, target_48, target_12)
and func_13(vn_971, vd_973, target_52, target_13)
and func_14(vn_971, vd_973, target_54, target_14)
and func_15(vn_971, vd_973, target_57, target_15)
and func_18(vp_973, target_18)
and func_19(vj_969, target_19)
and func_20(vp_973, target_20)
and func_21(vp_973, target_21)
and func_22(vcookie_len_970, target_22)
and func_23(vp_973, target_23)
and func_25(vp_973, target_25)
and func_26(vi_969, target_26)
and func_28(vp_973, target_28)
and func_29(vi_969, target_29)
and func_30(target_37, func, target_30)
and func_31(vj_969, vp_973, target_42, target_31)
and func_32(vp_973, target_46, target_32)
and func_33(vcookie_len_970, vp_973, target_48, target_33)
and func_34(vp_973, target_52, target_34)
and func_35(vi_969, vp_973, target_54, target_35)
and func_36(vi_969, vp_973, target_57, target_36)
and func_37(target_37)
and func_38(vp_973, vsession_length_1039, target_38)
and func_40(vj_969, vp_973, target_40)
and func_41(vi_969, vj_969, vn_971, vp_973, vd_973, target_41)
and func_42(target_42)
and func_43(vj_969, target_43)
and func_44(vj_969, vp_973, target_44)
and func_45(vcookie_len_970, vp_973, target_45)
and func_46(target_46)
and func_47(vcookie_len_970, vp_973, target_47)
and func_48(target_48)
and func_49(vcookie_len_970, target_49)
and func_50(vcookie_len_970, vp_973, target_50)
and func_51(vi_969, vp_973, target_51)
and func_52(target_52)
and func_53(vi_969, vp_973, target_53)
and func_54(target_54)
and func_55(vi_969, target_55)
and func_56(vp_973, target_56)
and func_57(target_57)
and func_58(vi_969, vp_973, target_58)
and func_59(vi_969, vj_969, target_59)
and vi_969.getType().hasName("int")
and vj_969.getType().hasName("int")
and vcookie_len_970.getType().hasName("unsigned int")
and vn_971.getType().hasName("long")
and vp_973.getType().hasName("unsigned char *")
and vd_973.getType().hasName("unsigned char *")
and vsession_length_1039.getType().hasName("unsigned int")
and vi_969.getParentScope+() = func
and vj_969.getParentScope+() = func
and vcookie_len_970.getParentScope+() = func
and vn_971.getParentScope+() = func
and vp_973.getParentScope+() = func
and vd_973.getParentScope+() = func
and vsession_length_1039.getParentScope+() = func
select func, "function relativepath is " + func.getFile().getRelativePath(), "function startline is " + func.getLocation().getStartLine()
